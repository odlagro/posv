import base64
import json
import os
import secrets
import time
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple

import requests
from flask import Flask, jsonify, redirect, render_template, request, session, url_for

# -----------------------------------------------------------------------------
# .env loader (simples, sem dependências)
# -----------------------------------------------------------------------------

def _load_dotenv_if_present() -> None:
  """
  Carrega variáveis do arquivo .env (se existir) para os.environ.
  - Não sobrescreve variáveis já existentes no ambiente.
  - Suporta linhas no formato CHAVE=VALOR (com ou sem aspas).
  """
  env_path = os.path.join(os.path.dirname(__file__), ".env")
  if not os.path.exists(env_path):
    return

  try:
    with open(env_path, "r", encoding="utf-8") as f:
      for raw in f.readlines():
        line = raw.strip()
        if not line or line.startswith("#"):
          continue
        if "=" not in line:
          continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        if k and k not in os.environ:
          os.environ[k] = v
  except Exception:
    # se falhar, apenas ignora (o app ainda pode funcionar se o ambiente estiver setado)
    return


_load_dotenv_if_present()

# -----------------------------------------------------------------------------
# Config / helpers
# -----------------------------------------------------------------------------

@dataclass
class AppConfig:
  # Tokens do Bling (obtidos via OAuth)
  bling_access_token: str = ""
  bling_refresh_token: str = ""
  bling_expires_at: float = 0.0  # epoch seconds (0 = desconhecido)

  # Melhor Envio
  melhorenvio_token: str = ""
  origin_zip_code: str = ""
  melhorenvio_env: str = "sandbox"  # ou "production"


CONFIG_PATH = os.path.join(os.path.dirname(__file__), "posv_config.json")


def load_config() -> AppConfig:
  if os.path.exists(CONFIG_PATH):
    try:
      with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        data = json.load(f) or {}
      # retrocompat: arquivos antigos podem não ter os novos campos
      return AppConfig(
        bling_access_token=data.get("bling_access_token", "") or "",
        bling_refresh_token=data.get("bling_refresh_token", "") or "",
        bling_expires_at=float(data.get("bling_expires_at", 0) or 0),
        melhorenvio_token=data.get("melhorenvio_token", "") or "",
        origin_zip_code=data.get("origin_zip_code", "") or "",
        melhorenvio_env=(data.get("melhorenvio_env", "sandbox") or "sandbox"),
      )
    except Exception:
      return AppConfig()
  return AppConfig()


def save_config(cfg: AppConfig) -> None:
  with open(CONFIG_PATH, "w", encoding="utf-8") as f:
    json.dump(asdict(cfg), f, ensure_ascii=False, indent=2)


def _env(name: str, default: str = "") -> str:
  return (os.environ.get(name) or default).strip()


def _bling_oauth_client() -> Tuple[str, str, str]:
  """
  Retorna (client_id, client_secret, redirect_uri) a partir do .env / ambiente.
  """
  cid = _env("BLING_CLIENT_ID")
  csec = _env("BLING_CLIENT_SECRET")
  ruri = _env("BLING_REDIRECT_URI")
  return cid, csec, ruri


app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False
app.secret_key = _env("FLASK_SECRET_KEY", "posv-dev-secret")  # necessário para session/state

# cache em memória dos produtos do Bling
bling_cache: Dict[str, Any] = {
  "ts": 0.0,
  "produtos": [],
  "total_ativos": 0,
}

# -----------------------------------------------------------------------------
# Bling - OAuth (igual ao ABLING: botão -> abre login do Bling)
# -----------------------------------------------------------------------------

def _bling_authorize_url(state: str) -> str:
  """
  Endpoint de autorização do Bling (API v3 OAuth).
  Documentação oficial indica o endpoint `authorize` no domínio bling.com.br.
  """
  client_id, _, redirect_uri = _bling_oauth_client()
  # Observação: redirect_uri é opcional na RFC, mas mantemos para clareza.
  # O Bling usa os valores cadastrados no app mesmo que você envie aqui.
  params = {
    "client_id": client_id,
    "response_type": "code",
    "state": state,
  }
  # incluir redirect_uri se estiver definido (recomendado)
  if redirect_uri:
    params["redirect_uri"] = redirect_uri

  from urllib.parse import urlencode
  return "https://www.bling.com.br/Api/v3/oauth/authorize?" + urlencode(params)


def _bling_token_url() -> str:
  # Documentação descreve POST para o endpoint `/token` do authorization server.
  return "https://www.bling.com.br/Api/v3/oauth/token"


def _basic_auth_header(client_id: str, client_secret: str) -> str:
  raw = f"{client_id}:{client_secret}".encode("utf-8")
  return "Basic " + base64.b64encode(raw).decode("ascii")


def _bling_exchange_code_for_tokens(code: str) -> Dict[str, Any]:
  """
  Troca authorization_code por access_token e refresh_token.
  O Bling exige autenticação Basic no header (client_id:client_secret em base64).
  """
  client_id, client_secret, redirect_uri = _bling_oauth_client()
  if not client_id or not client_secret:
    raise RuntimeError("BLING_CLIENT_ID / BLING_CLIENT_SECRET não configurados no .env.")

  headers = {
    "Accept": "application/json",
    "Content-Type": "application/x-www-form-urlencoded",
    "Authorization": _basic_auth_header(client_id, client_secret),
  }

  data = {
    "grant_type": "authorization_code",
    "code": code,
  }
  # alguns provedores exigem redirect_uri na troca; mantemos se estiver setado
  if redirect_uri:
    data["redirect_uri"] = redirect_uri

  resp = requests.post(_bling_token_url(), headers=headers, data=data, timeout=30)
  if not resp.ok:
    raise RuntimeError(f"Falha ao obter tokens do Bling: {resp.status_code} - {resp.text[:300]}")
  return resp.json() if resp.text else {}


def _bling_refresh_access_token(refresh_token: str) -> Dict[str, Any]:
  """
  Gera um novo access_token usando refresh_token.
  """
  client_id, client_secret, redirect_uri = _bling_oauth_client()
  if not client_id or not client_secret:
    raise RuntimeError("BLING_CLIENT_ID / BLING_CLIENT_SECRET não configurados no .env.")
  if not refresh_token:
    raise RuntimeError("Refresh token vazio. Refaça a conexão com o Bling.")

  headers = {
    "Accept": "application/json",
    "Content-Type": "application/x-www-form-urlencoded",
    "Authorization": _basic_auth_header(client_id, client_secret),
  }

  data = {
    "grant_type": "refresh_token",
    "refresh_token": refresh_token,
  }
  if redirect_uri:
    data["redirect_uri"] = redirect_uri

  resp = requests.post(_bling_token_url(), headers=headers, data=data, timeout=30)
  if not resp.ok:
    raise RuntimeError(f"Falha ao renovar token do Bling: {resp.status_code} - {resp.text[:300]}")
  return resp.json() if resp.text else {}


def _ensure_valid_bling_token(cfg: AppConfig) -> AppConfig:
  """
  Se o access_token estiver expirado (ou prestes a expirar), tenta renovar com refresh_token.
  """
  # se não temos expiração, não força refresh automaticamente
  if not cfg.bling_access_token:
    return cfg

  # 60s de folga
  if cfg.bling_expires_at and time.time() > (cfg.bling_expires_at - 60):
    if cfg.bling_refresh_token:
      data = _bling_refresh_access_token(cfg.bling_refresh_token)
      access = data.get("access_token") or ""
      refresh = data.get("refresh_token") or cfg.bling_refresh_token
      expires_in = float(data.get("expires_in") or 0)  # segundos
      if access:
        cfg.bling_access_token = access
      cfg.bling_refresh_token = refresh
      if expires_in:
        cfg.bling_expires_at = time.time() + expires_in
      save_config(cfg)
  return cfg


@app.route("/bling/login")
def bling_login():
  """
  Ao clicar em "Conectar Bling" abre a tela de login/consentimento do Bling.
  """
  client_id, client_secret, redirect_uri = _bling_oauth_client()
  if not client_id or not client_secret or not redirect_uri:
    # não quebra o app: mostra um erro simples na própria tela inicial
    return (
      "Erro: configure BLING_CLIENT_ID, BLING_CLIENT_SECRET e BLING_REDIRECT_URI no arquivo .env.",
      500,
    )

  state = secrets.token_urlsafe(24)
  session["bling_oauth_state"] = state
  return redirect(_bling_authorize_url(state))


@app.route("/callback")
def bling_callback():
  """
  Callback configurado no app do Bling (BLING_REDIRECT_URI).
  Recebe ?code=...&state=...
  """
  code = (request.args.get("code") or "").strip()
  state = (request.args.get("state") or "").strip()
  erro = (request.args.get("error") or "").strip()

  if erro:
    return f"Autorização negada ou falhou no Bling: {erro}", 400

  expected_state = session.get("bling_oauth_state")
  if expected_state and state != expected_state:
    return "State inválido na resposta do Bling (possível CSRF). Tente conectar novamente.", 400

  if not code:
    return "Callback do Bling sem o parâmetro 'code'.", 400

  try:
    data = _bling_exchange_code_for_tokens(code)
  except Exception as e:
    return f"Erro ao trocar code por tokens: {e}", 500

  access_token = (data.get("access_token") or "").strip()
  refresh_token = (data.get("refresh_token") or "").strip()
  expires_in = float(data.get("expires_in") or 0)  # segundos

  if not access_token:
    return f"Resposta do Bling não retornou access_token. Resposta: {data}", 500

  cfg = load_config()
  cfg.bling_access_token = access_token
  cfg.bling_refresh_token = refresh_token or cfg.bling_refresh_token
  cfg.bling_expires_at = (time.time() + expires_in) if expires_in else 0.0
  save_config(cfg)

  # limpa cache (novo token pode ter escopos diferentes / outra conta)
  global bling_cache
  bling_cache["ts"] = 0.0
  bling_cache["produtos"] = []
  bling_cache["total_ativos"] = 0

  return redirect(url_for("index"))


# -----------------------------------------------------------------------------
# Views
# -----------------------------------------------------------------------------

@app.route("/")
def index():
  return render_template("index.html")


@app.route("/config", methods=["GET", "POST"])
def config_view():
  cfg = load_config()

  if request.method == "POST":
    # Bling: agora é via OAuth (não editável aqui). Mantemos retrocompat se já existir.
    cfg.melhorenvio_token = request.form.get("melhorenvio_token", "").strip()
    cfg.origin_zip_code = request.form.get("origin_zip_code", "").strip()
    cfg.melhorenvio_env = request.form.get("melhorenvio_env", "sandbox").strip() or "sandbox"

    save_config(cfg)
    return redirect(url_for("config_view"))

  # status da conexão (para o template)
  conectado = bool(cfg.bling_access_token)
  return render_template("config.html", cfg=cfg, bling_conectado=conectado)


# -----------------------------------------------------------------------------
# Bling API
# -----------------------------------------------------------------------------

def _get_bling_base_url() -> str:
  return "https://api.bling.com.br/Api/v3"


def _bling_headers(access_token: str) -> Dict[str, str]:
  return {
    "Accept": "application/json",
    "Authorization": f"Bearer {access_token}",
  }


def _simplificar_imagem(produto: Dict[str, Any]) -> Optional[str]:
  """
  Tenta extrair o link de imagem de várias estruturas possíveis do Bling.
  Assim, mesmo que o formato mude um pouco, ainda teremos alguma chance
  de pegar a URL.
  """
  imagem = produto.get("imagem") or produto.get("image") or produto.get("imagens")

  if isinstance(imagem, str):
    return imagem.strip() or None

  if isinstance(imagem, dict):
    for chave in ("url", "link", "href", "urlImagem", "urlImagemMiniatura"):
      if imagem.get(chave):
        return str(imagem[chave]).strip()

  if isinstance(imagem, list) and imagem:
    primeiro = imagem[0]
    if isinstance(primeiro, dict):
      for chave in ("url", "link", "href", "urlImagem", "urlImagemMiniatura"):
        if primeiro.get(chave):
          return str(primeiro[chave]).strip()

  return None


def _simplificar_produto(produto: Dict[str, Any]) -> Dict[str, Any]:
  """
  Converte o produto cru do Bling em um formato simplificado para o front.
  """
  sku = (
    produto.get("codigo")
    or produto.get("codigoItem")
    or produto.get("idProduto")
    or produto.get("id")
    or ""
  )

  nome = (
    produto.get("descricao")
    or produto.get("nome")
    or produto.get("descricaoProduto")
    or f"Produto {produto.get('id')}"
  )

  preco = produto.get("preco") or produto.get("precoVenda") or produto.get("valorUnitario") or 0
  estoque = produto.get("estoque") or produto.get("saldo") or produto.get("quantidadeEstoque")

  # Peso: guardamos a informação original (se existir) para exibir na tela,
  # mas se não vier definido usamos 0.5 kg internamente (frete).
  peso_original = (
    produto.get("pesoLiquido")
    or produto.get("pesoBruto")
    or produto.get("peso_liquido")
    or produto.get("peso_bruto")
  )

  peso_exibir: Optional[float]
  if peso_original is None or peso_original == "":
    peso_exibir = None
  else:
    try:
      peso_exibir = float(str(peso_original).replace(",", "."))
    except Exception:
      peso_exibir = None

  imagem_url = _simplificar_imagem(produto)

  return {
    "id": produto.get("id") or produto.get("idProduto") or sku or nome,
    "sku": str(sku) if sku is not None else "",
    "nome": str(nome),
    "preco": float(preco) if isinstance(preco, (int, float)) else float(str(preco).replace(",", ".") or 0),
    "peso": peso_exibir,  # pode ser None -> front mostra vazio, calcula frete com default
    "estoque": estoque,
    "imagem_url": imagem_url,
  }


def _buscar_produtos_bling(access_token: str) -> Tuple[List[Dict[str, Any]], int]:
  """
  Busca todos os produtos ATIVOS do Bling paginando.
  """
  base_url = _get_bling_base_url()
  headers = _bling_headers(access_token)

  pagina = 1
  limite = 100
  todos: List[Dict[str, Any]] = []
  total_ativos = 0

  while True:
    params = {
      "pagina": pagina,
      "limite": limite,
      "criterio": 2,  # 2 = somente ativos
    }
    url = f"{base_url}/produtos"
    resp = requests.get(url, headers=headers, params=params, timeout=30)

    if resp.status_code == 401:
      raise RuntimeError("Bling retornou 401 (Unauthorized). Faça 'Conectar Bling' novamente.")
    if not resp.ok:
      raise RuntimeError(
        f"Erro ao buscar produtos no Bling: {resp.status_code} - {resp.text[:200]}"
      )

    data = resp.json()
    itens = data.get("data") or data.get("produtos") or []

    if not isinstance(itens, list) or not itens:
      break

    for bruto in itens:
      prod = bruto.get("produto") if isinstance(bruto, dict) and "produto" in bruto else bruto
      simplificado = _simplificar_produto(prod)
      todos.append(simplificado)
      total_ativos += 1

    if len(itens) < limite:
      break

    pagina += 1
    time.sleep(0.1)

  return todos, total_ativos


def _obter_produtos_cache(access_token: str, force_reload: bool = False) -> Tuple[List[Dict[str, Any]], int]:
  global bling_cache

  agora = time.time()
  cache_valido = (agora - bling_cache["ts"]) < 15 * 60  # 15 minutos

  if not force_reload and cache_valido and bling_cache["produtos"]:
    return bling_cache["produtos"], bling_cache["total_ativos"]

  produtos, total_ativos = _buscar_produtos_bling(access_token)
  bling_cache["ts"] = agora
  bling_cache["produtos"] = produtos
  bling_cache["total_ativos"] = total_ativos
  return produtos, total_ativos


@app.route("/api/produtos")
def api_produtos():
  cfg = load_config()
  cfg = _ensure_valid_bling_token(cfg)

  if not cfg.bling_access_token:
    return (
      jsonify({"error": "Clique em 'Conectar Bling' para autorizar e gerar o token automaticamente."}),
      400,
    )

  busca = (request.args.get("busca") or "").strip().lower()
  reload = request.args.get("reload") == "1"

  try:
    produtos, total_ativos = _obter_produtos_cache(cfg.bling_access_token, force_reload=reload)
  except Exception as e:
    return jsonify({"error": str(e)}), 500

  if busca:
    # Regra: quando o termo bater exatamente com algum SKU, retornar SOMENTE o(s) SKU(s) exato(s).
    # Isso evita que, por exemplo, "559" traga também "1559", "5590", etc.
    busca_sku = busca  # já está em lowercase
    exatos = [p for p in produtos if (str(p.get("sku") or "").strip().lower() == busca_sku)]
    if exatos:
      filtrados = exatos
    else:
      filtrados = []
      for p in produtos:
        nome = (p.get("nome") or "").lower()
        sku = (p.get("sku") or "").lower()
        if busca in nome or busca in sku:
          filtrados.append(p)
  else:
    filtrados = produtos[:100]

  return jsonify(
    {
      "produtos": filtrados,
      "total_ativos": total_ativos,
    }
  )


# -----------------------------------------------------------------------------
# Melhor Envio - cálculo por pacotes
# -----------------------------------------------------------------------------

def _melhorenvio_base_url(env: str) -> str:
  return "https://sandbox.melhorenvio.com.br/api/v2/me" if env != "production" else "https://www.melhorenvio.com.br/api/v2/me"


def _melhorenvio_headers(token: str) -> Dict[str, str]:
  return {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "Authorization": f"Bearer {token}",
    "User-Agent": "POSV (contato@seudominio.com)",
  }


@app.route("/api/calcular-frete", methods=["POST"])
def api_calcular_frete():
  cfg = load_config()
  if not cfg.melhorenvio_token or not cfg.origin_zip_code:
    return (
      jsonify(
        {
          "error": "Configure o token do Melhor Envio e o CEP de origem na tela de configurações."
        }
      ),
      400,
    )

  payload = request.get_json(silent=True) or {}
  cep_destino = (payload.get("cep_destino") or "").strip()
  packages = payload.get("packages") or []
  provider = payload.get("provider") or "melhorenvio"

  if not cep_destino:
    return jsonify({"error": "CEP de destino não informado."}), 400
  if not packages:
    return jsonify({"error": "Nenhum pacote informado para cotação."}), 400

  body = {
    "from": {"postal_code": cfg.origin_zip_code},
    "to": {"postal_code": cep_destino},
    "packages": [],
    "options": {
      "receipt": False,
      "own_hand": False,
    },
    "services": "",  # deixar em branco para retornar todos
  }

  for p in packages:
    try:
      width = float(p.get("width", 0))
      height = float(p.get("height", 0))
      length = float(p.get("length", 0))
      weight = float(p.get("weight", 0))
      insurance = float(p.get("insurance", 0))
    except Exception:
      continue

    if not (width and height and length and weight):
      continue

    body["packages"].append(
      {
        "width": width,
        "height": height,
        "length": length,
        "weight": weight,
        "insurance": insurance,
      }
    )

  if not body["packages"]:
    return jsonify({"error": "Os dados dos pacotes são inválidos."}), 400

  base_url = _melhorenvio_base_url(cfg.melhorenvio_env)
  url = f"{base_url}/shipment/calculate"
  headers = _melhorenvio_headers(cfg.melhorenvio_token)

  try:
    resp = requests.post(url, headers=headers, json=body, timeout=30)
  except Exception as e:
    return jsonify({"error": f"Erro de comunicação com Melhor Envio: {e}"}), 500

  if resp.status_code == 401:
    return jsonify({"error": "401 do Melhor Envio (Unauthorized). Verifique o token."}), 401

  if not resp.ok:
    return jsonify({"error": f"Erro HTTP ao calcular frete: {resp.status_code} {resp.text}"}), 500

  data = resp.json()

  opcoes: List[Dict[str, Any]] = []

  if isinstance(data, list):
    for servico in data:
      valor = servico.get("price") or servico.get("cost") or 0
      nome = servico.get("name") or servico.get("company", {}).get("name") or "Serviço"
      prazo = servico.get("delivery_time") or servico.get("delivery_range") or {}
      opcoes.append(
        {
          "nome": nome,
          "preco": float(valor),
          "prazo": prazo,
        }
      )
  elif isinstance(data, dict):
    for key, servico in data.items():
      if not isinstance(servico, dict):
        continue
      valor = servico.get("price") or servico.get("cost") or 0
      nome = servico.get("name") or servico.get("company", {}).get("name") or str(key)
      prazo = servico.get("delivery_time") or servico.get("delivery_range") or {}
      opcoes.append(
        {
          "nome": nome,
          "preco": float(valor),
          "prazo": prazo,
        }
      )

  return jsonify({"opcoes": opcoes})


# -----------------------------------------------------------------------------
# main
# -----------------------------------------------------------------------------

if __name__ == "__main__":
  port = int(os.environ.get("PORT", "6262"))
  app.run(host="0.0.0.0", port=port, debug=True)
