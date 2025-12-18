import base64
import json
import os
import secrets
import time
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple

import requests
import xml.etree.ElementTree as ET
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

def _logo_orcamento_path() -> str:
  """Caminho absoluto da logo do orçamento (PNG fixo)."""
  return os.path.join(os.path.dirname(__file__), "static", "uploads", "logo_orcamento.png")


def _salvar_logo_orcamento(file_storage) -> None:
  """
  Salva a logo enviada em static/uploads/logo_orcamento.png.
  - Se Pillow estiver disponível, converte para PNG (garante compatibilidade).
  - Caso contrário, salva o binário como está (ainda funcionando na maioria dos navegadores).
  """
  if not file_storage:
    return
  # cria pasta
  out_path = _logo_orcamento_path()
  os.makedirs(os.path.dirname(out_path), exist_ok=True)

  try:
    # tenta converter com Pillow (se existir)
    from PIL import Image  # type: ignore
    img = Image.open(file_storage.stream)
    # garante modo compatível
    if img.mode not in ("RGB", "RGBA"):
      img = img.convert("RGBA")
    # se tiver alpha, mantém; senão RGB
    if img.mode == "RGBA":
      img.save(out_path, format="PNG")
    else:
      img.convert("RGB").save(out_path, format="PNG")
  except Exception:
    # fallback: salva como veio
    file_storage.save(out_path)


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
    # Upload da logo do orçamento (salva em static/uploads/logo_orcamento.png)
    logo_file = request.files.get("logo_orcamento")
    if logo_file and getattr(logo_file, "filename", ""):
      _salvar_logo_orcamento(logo_file)

    # Bling: agora é via OAuth (não editável aqui). Mantemos retrocompat se já existir.
    cfg.melhorenvio_token = request.form.get("melhorenvio_token", "").strip()
    cfg.origin_zip_code = request.form.get("origin_zip_code", "").strip()
    cfg.melhorenvio_env = request.form.get("melhorenvio_env", "sandbox").strip() or "sandbox"

    save_config(cfg)
    return redirect(url_for("config_view"))

  # status da conexão (para o template)
  conectado = bool(cfg.bling_access_token)
  # Logo do orçamento (para preview na tela)
  logo_orcamento_url = None
  try:
    if os.path.exists(_logo_orcamento_path()):
      logo_orcamento_url = url_for("static", filename="uploads/logo_orcamento.png", v=str(int(time.time())))
  except Exception:
    logo_orcamento_url = None
  return render_template("config.html", cfg=cfg, bling_conectado=conectado, logo_orcamento_url=logo_orcamento_url)


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
  # Campo oficial na API do Bling (v3): imagemURL
  for chave in ("imagemURL", "imagemUrl", "imageURL", "imageUrl"):
    if produto.get(chave):
      return str(produto.get(chave)).strip() or None

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
# Correios - CalcPrecoPrazo (API oficial / calculador)
# -----------------------------------------------------------------------------

_CORREIOS_CALC_URL = "https://ws.correios.com.br/calculador/CalcPrecoPrazo.aspx"

def _so_digitos(s: str) -> str:
  return "".join(ch for ch in (s or "") if ch.isdigit())

def _to_num_str(v: Any) -> str:
  """
  Correios espera números em formato com ponto decimal.
  """
  try:
    if v is None:
      return "0"
    if isinstance(v, str):
      v = v.strip().replace(",", ".")
    return str(float(v))
  except Exception:
    return "0"

def _parse_correios_valor(s: Optional[str]) -> float:
  if not s:
    return 0.0
  try:
    return float(str(s).strip().replace(".", "").replace(",", "."))
  except Exception:
    try:
      return float(str(s).strip().replace(",", "."))
    except Exception:
      return 0.0

def _correios_cotar_servico(
  cep_origem: str,
  cep_destino: str,
  peso_kg: Any,
  comprimento_cm: Any,
  altura_cm: Any,
  largura_cm: Any,
  codigo_servico: str,
  valor_declarado: Any = 0,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
  """
  Retorna (opcao, erro_msg). opcao no formato do front: {nome, preco, prazo}
  """
  params = {
    "nCdEmpresa": "",
    "sDsSenha": "",
    "nCdServico": str(codigo_servico),
    "sCepOrigem": _so_digitos(cep_origem),
    "sCepDestino": _so_digitos(cep_destino),
    "nVlPeso": _to_num_str(peso_kg),
    "nCdFormato": "1",
    "nVlComprimento": _to_num_str(comprimento_cm),
    "nVlAltura": _to_num_str(altura_cm),
    "nVlLargura": _to_num_str(largura_cm),
    "nVlDiametro": "0",
    "sCdMaoPropria": "N",
    "nVlValorDeclarado": _to_num_str(valor_declarado or 0),
    "sCdAvisoRecebimento": "N",
    "StrRetorno": "xml",
  }

  try:
    resp = requests.get(_CORREIOS_CALC_URL, params=params, timeout=30)
  except Exception as e:
    return None, f"Erro de comunicação com Correios: {e}"

  if not resp.ok:
    return None, f"Erro HTTP Correios: {resp.status_code} {resp.text[:200]}"

  try:
    root = ET.fromstring(resp.content)
  except Exception:
    return None, "Resposta inválida dos Correios (XML não pôde ser lido)."

  # Os campos vêm dentro de um <cServico>
  erro = root.findtext(".//Erro") or ""
  msg_erro = (root.findtext(".//MsgErro") or "").strip()
  valor = root.findtext(".//Valor") or ""
  prazo = root.findtext(".//PrazoEntrega") or ""

  if erro and erro.strip() not in ("0", "000"):
    return None, msg_erro or f"Erro dos Correios (código {erro})."

  preco = _parse_correios_valor(valor)
  try:
    prazo_int = int(str(prazo).strip())
  except Exception:
    prazo_int = 0

  opcao = {
    "nome": "PAC" if str(codigo_servico) == "04510" else "SEDEX",
    "preco": float(preco),
    "prazo": prazo_int,
  }
  return opcao, None

# -----------------------------------------------------------------------------
# Melhor Envio - cálculo por pacotes
# -----------------------------------------------------------------------------

def _melhorenvio_base_url(env: str) -> str:
  # Sandbox real (mesmo domínio usado pela calculadora web app-sandbox)
  if env != "production":
    return "https://sandbox.melhorenvio.com.br/api/v2/me"
  return "https://www.melhorenvio.com.br/api/v2/me"


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

  payload = request.get_json(silent=True) or {}
  cep_destino = (payload.get("cep_destino") or "").strip()
  cep_destino = "".join([c for c in cep_destino if c.isdigit()])
  packages = payload.get("packages") or []
  provider = (payload.get("provider") or "melhorenvio").strip().lower()

  if not cep_destino:
    return jsonify({"error": "CEP de destino não informado."}), 400
  if not packages:
    return jsonify({"error": "Nenhum pacote informado para cotação."}), 400

  # Normaliza CEPs
  cep_destino = _so_digitos(cep_destino)
  cep_origem = _so_digitos(cfg.origin_zip_code or "")

  if provider == "correios":
    # Para Correios precisamos, no mínimo, do CEP de origem.
    if not cep_origem:
      return (
        jsonify(
          {
            "error": "Configure o CEP de origem na tela de configurações para cotar pelos Correios."
          }
        ),
        400,
      )

    # O sistema trabalha com 1 pacote (o front envia 1), mas aceitamos o primeiro válido.
    p0 = packages[0] if packages else {}
    try:
      width = float(str(p0.get("width", 0)).replace(",", "."))
      height = float(str(p0.get("height", 0)).replace(",", "."))
      length = float(str(p0.get("length", 0)).replace(",", "."))
      weight = float(str(p0.get("weight", 0)).replace(",", "."))
      insurance = float(str(p0.get("insurance", 0) or 0).replace(",", "."))
    except Exception:
      return jsonify({"error": "Os dados do pacote são inválidos."}), 400

    if not (width and height and length and weight):
      return jsonify({"error": "Preencha largura, altura, comprimento e peso para cotar pelos Correios."}), 400

    # Correios: cota PAC e SEDEX
    opcoes: List[Dict[str, Any]] = []

  def _money_to_float(v: Any) -> float:
    """Converte preços do Melhor Envio para float (aceita string com vírgula/ponto)."""
    if v is None:
      return 0.0
    if isinstance(v, (int, float)):
      return float(v)
    s = str(v).strip()
    # padrão BR -> troca vírgula por ponto
    s = s.replace(",", ".")
    try:
      return float(s)
    except Exception:
      return 0.0
    if isinstance(v, (int, float)):
      return float(v)
    try:
      s = str(v).strip().replace(".", "").replace(",", ".")
      # Se veio tipo "31.05" já fica ok após replace(".", "") -> isso quebraria. Então tratamos:
      # estratégia: primeiro tenta direto, se falhar aplica troca de vírgula.
    except Exception:
      return 0.0
    # Tenta parse direto primeiro
    try:
      return float(str(v).strip().replace(",", "."))
    except Exception:
      return 0.0

    # PAC (04510)
    pac, err_pac = _correios_cotar_servico(
      cep_origem=cep_origem,
      cep_destino=cep_destino,
      peso_kg=weight,
      comprimento_cm=length,
      altura_cm=height,
      largura_cm=width,
      codigo_servico="04510",
      valor_declarado=0,  # mantemos 0 para não alterar regra atual
    )
    if pac:
      opcoes.append(pac)

    sedex, err_sedex = _correios_cotar_servico(
      cep_origem=cep_origem,
      cep_destino=cep_destino,
      peso_kg=weight,
      comprimento_cm=length,
      altura_cm=height,
      largura_cm=width,
      codigo_servico="04014",
      valor_declarado=0,
    )
    if sedex:
      opcoes.append(sedex)

    if not opcoes:
      # retorna o erro mais relevante
      msg = err_pac or err_sedex or "Não foi possível cotar pelos Correios."
      return jsonify({"error": msg}), 500

    return jsonify({"opcoes": opcoes})

  # ---------------------------------------------------------------------------
  # Melhor Envio (padrão)
  # ---------------------------------------------------------------------------
  if not cfg.melhorenvio_token or not cep_origem:
    return (
      jsonify(
        {
          "error": "Configure o token do Melhor Envio e o CEP de origem na tela de configurações."
        }
      ),
      400,
    )

  body = {
    "from": {"postal_code": cep_origem},
    "to": {"postal_code": cep_destino},
    "products": [],
    "options": {
      "receipt": False,
      "own_hand": False,
    },
    # Para bater com a calculadora web do sandbox, pedimos pelo menos PAC/SEDEX/mini-envios.
    # (IDs do Melhor Envio: 1=PAC, 2=SEDEX, 18=Mini Envios)
    "services": "1,2,18",
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

    body["products"].append(
      {
        "id": "POSV_ITEM",
        "width": width,
        "height": height,
        "length": length,
        "weight": max(weight, 0.1),
        "insurance_value": insurance,
        "quantity": int(p.get("quantity") or 1),
      }
    )

  if not body["products"]:
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
      valor = servico.get("custom_price") or servico.get("price") or servico.get("cost") or 0
      nome = servico.get("name") or servico.get("company", {}).get("name") or "Serviço"
      prazo = servico.get("custom_delivery_time") or servico.get("delivery_time") or servico.get("delivery_range") or {}
      opcoes.append(
        {
          "nome": nome,
          "preco": _money_to_float(valor),
          "prazo": prazo,
        }
      )
  elif isinstance(data, dict):
    for key, servico in data.items():
      if not isinstance(servico, dict):
        continue
      valor = servico.get("custom_price") or servico.get("price") or servico.get("cost") or 0
      nome = servico.get("name") or servico.get("company", {}).get("name") or str(key)
      prazo = servico.get("custom_delivery_time") or servico.get("delivery_time") or servico.get("delivery_range") or {}
      opcoes.append(
        {
          "nome": nome,
          "preco": _money_to_float(valor),
          "prazo": prazo,
        }
      )

  return jsonify({"opcoes": opcoes})


# -----------------------------------------------------------------------------
# main
# -----------------------------------------------------------------------------


# =========================
# ORÇAMENTO (ETAPA 2)
# Gera imagem PNG local em static/uploads/orcamento.png
# NÃO altera Bling / Melhor Envio / Frete
# =========================
@app.post("/api/orcamento/gerar")
def api_orcamento_gerar():
  """
  Gera um PNG local do orçamento em static/uploads/orcamento.png.
  - Subtotal = soma dos produtos
  - Frete = valor informado pelo front (frete selecionado)
  - Total = Subtotal + Frete
  - Data + validade (data + 10 dias)
  - Inclui foto do produto se itens[i].imagem_url existir
  """
  try:
    from PIL import Image, ImageDraw, ImageFont
  except Exception as e:
    return jsonify({"ok": False, "error": "Pillow não instalado (pip install pillow).", "detail": str(e)}), 500

  import io
  import datetime as _dt

  payload = request.get_json(silent=True) or {}
  itens = payload.get("itens") or payload.get("items") or []
  frete = payload.get("frete") or 0
  frete_nome = payload.get("frete_nome") or ""

  if not isinstance(itens, list):
    return jsonify({"ok": False, "error": "Payload inválido: itens precisa ser lista."}), 400

  def _to_float(v):
    try:
      if v is None:
        return 0.0
      if isinstance(v, str):
        v = v.strip().replace(".", "").replace(",", ".") if "," in v else v.strip().replace(",", ".")
      return float(v)
    except Exception:
      return 0.0

  frete = _to_float(frete)

  def brl(v):
    try:
      v = float(v)
    except Exception:
      v = 0.0
    s = f"{v:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    return f"R$ {s}"

  # Datas
  hoje = _dt.date.today()
  valido_ate = hoje + _dt.timedelta(days=10)
  data_str = hoje.strftime("%d/%m/%Y")
  valido_str = valido_ate.strftime("%d/%m/%Y")

  # Fonte
  def _try_font(size: int, bold: bool = False):
    # tenta fontes comuns
    candidates = []
    if bold:
      candidates += ["arialbd.ttf", "Arial Bold.ttf", "Arialbd.ttf"]
    candidates += ["arial.ttf", "Arial.ttf", "DejaVuSans.ttf"]
    for fp in candidates:
      try:
        return ImageFont.truetype(fp, size)
      except Exception:
        pass
    return ImageFont.load_default()

  font_title = _try_font(34, bold=True)
  font_h = _try_font(16, bold=True)
  font = _try_font(15, bold=False)
  font_small = _try_font(13, bold=False)
  font_small_bold = _try_font(13, bold=True)
  font_total = _try_font(22, bold=True)

  # Layout
  w = 1200
  margin = 40
  header_h = 190
  row_h = 86  # alto para foto
  table_header_h = 38

  # calcula subtotal
  subtotal = 0.0
  norm_items = []
  for it in itens:
    try:
      nome = str(it.get("nome") or it.get("name") or "").strip()
      sku = str(it.get("sku") or it.get("codigo") or it.get("code") or "").strip()
      un = str(it.get("un") or "UN").strip() or "UN"
      qtd = _to_float(it.get("quantidade") or it.get("qty") or 1)
      if qtd <= 0:
        qtd = 1.0
      preco = _to_float(it.get("preco") or it.get("price") or 0)
      img_url = str(it.get("imagem_url") or it.get("imagem") or it.get("image_url") or "").strip()
      total_item = preco * qtd
      subtotal += total_item
      norm_items.append({
        "nome": nome,
        "sku": sku,
        "un": un,
        "qtd": qtd,
        "preco": preco,
        "total": total_item,
        "imagem_url": img_url,
      })
    except Exception:
      continue

  total_geral = subtotal + frete

  # altura dinâmica
  rows = max(1, len(norm_items))
  footer_h = 190
  h = header_h + table_header_h + rows * row_h + footer_h

  img = Image.new("RGB", (w, h), "white")
  draw = ImageDraw.Draw(img)

  # Logo (upload da ETAPA 1) - maior e melhor posicionada
  logo_path = os.path.join("static", "uploads", "logo_orcamento.png")
  if os.path.exists(logo_path):
    try:
      logo = Image.open(logo_path).convert("RGBA")
      logo.thumbnail((260, 120))
      img.paste(logo, (margin, 30), logo)
    except Exception:
      pass

  # Cabeçalho direito (mantém fixo)
  header_right = [
    "ODL AGRO COMERCIO E SERVICOS - EIRELI",
    "AV. HUGO LOPES NALY, Nº 113, GALPAO",
    "35200000 - Aimorés, MG",
    "CNPJ: 32.138.933/0001-36",
  ]
  y0 = 32

  # (2) Dados da empresa à direita
  for i, line in enumerate(header_right):
    bb = draw.textbbox((0, 0), line, font=font_small)
    lw = bb[2] - bb[0]
    draw.text((w - margin - lw, y0 + i * 18), line, fill="black", font=font_small)

  # (1) Data no centro (negrito)
  date_txt = f"Data: {data_str}"
  db = draw.textbbox((0, 0), date_txt, font=font_small_bold)
  dw = db[2] - db[0]
  draw.text(((w - dw)//2, y0), date_txt, fill="black", font=font_small_bold)

  # Título + datas
  # Título (central) + Data (direita) no mesmo cabeçalho
  title_txt = "ORÇAMENTO"
  tb = draw.textbbox((0, 0), title_txt, font=font_title)
  tw = tb[2] - tb[0]
  draw.text(((w - tw)//2, 60), title_txt, fill="black", font=font_title)

  dw = db[2] - db[0]


  # Tabela
  table_x = margin
  table_y = header_h
  table_w = w - (margin * 2)

  # Colunas (inclui Imagem)
  cols = [
    ("Imagem", 0.00, 0.14),
    ("Descrição", 0.14, 0.58),
    ("Código", 0.58, 0.70),
    ("Un.", 0.70, 0.76),
    ("Qtd.", 0.76, 0.83),
    ("V. unit.", 0.83, 0.92),
    ("V. total", 0.92, 1.00),
  ]

  # header row
  draw.rectangle([table_x, table_y, table_x + table_w, table_y + table_header_h], outline="black", width=2)
  for title, a, b in cols:
    x1 = table_x + int(table_w * a)
    draw.line([x1, table_y, x1, table_y + table_header_h], fill="black", width=2)
    draw.text((x1 + 8, table_y + 10), title, fill="black", font=font_h)

  # helper: baixar imagem
  def _baixar_img(url: str):
    if not url:
      return None
    try:
      r = requests.get(url, timeout=10)
      if not r.ok or not r.content:
        return None
      return Image.open(io.BytesIO(r.content)).convert("RGB")
    except Exception:
      return None

  y = table_y + table_header_h
  for it in norm_items[:rows]:
    draw.rectangle([table_x, y, table_x + table_w, y + row_h], outline="black", width=1)
    # linhas verticais
    for _, a, _b in cols[1:]:
      x1 = table_x + int(table_w * a)
      draw.line([x1, y, x1, y + row_h], fill="black", width=1)

    # imagem
    img_cell_x1 = table_x + int(table_w * cols[0][1]) + 10
    img_cell_y1 = y + 10
    pic = _baixar_img(it.get("imagem_url") or "")
    if pic:
      pic.thumbnail((int(table_w*0.14)-20, row_h-20))
      img.paste(pic, (img_cell_x1, img_cell_y1))
    else:
      # placeholder discreto
      draw.rectangle([img_cell_x1, img_cell_y1, img_cell_x1 + int(table_w*0.14)-30, img_cell_y1 + row_h-20], outline="#cccccc", width=1)
      draw.multiline_text((img_cell_x1+8, img_cell_y1+22), "SEM\nFOTO", fill="#777777", font=font_small, spacing=2, align="left")

    # textos
    desc = it["nome"]
    if len(desc) > 60:
      desc = desc[:57] + "..."
    draw.text((table_x + int(table_w*0.14) + 10, y + 12), desc, fill="black", font=font)
    draw.text((table_x + int(table_w*0.58) + 8, y + 12), it["sku"], fill="black", font=font)
    draw.text((table_x + int(table_w*0.70) + 8, y + 12), it["un"], fill="black", font=font)
    draw.text((table_x + int(table_w*0.76) + 8, y + 12), f"{it['qtd']:.0f}", fill="black", font=font)
    draw.text((table_x + int(table_w*0.83) + 8, y + 12), brl(it["preco"]), fill="black", font=font)
    draw.text((table_x + int(table_w*0.92) + 8, y + 12), brl(it["total"]), fill="black", font=font)

    y += row_h

  # Resumo (Subtotal / Frete / Total)
  box_w = 460
  box_x = w - margin - box_w
  box_y = y + 24

  draw.rectangle([box_x, box_y, box_x + box_w, box_y + 120], outline="black", width=2)
  draw.text((box_x + 16, box_y + 14), "Subtotal (produtos)", fill="black", font=font_h)
  x_right = box_x + box_w - 16
  def _right_x(txt, font_obj):
    try:
      return x_right - draw.textlength(txt, font=font_obj)
    except Exception:
      try:
        bb = font_obj.getbbox(txt)
        return x_right - (bb[2] - bb[0])
      except Exception:
        return x_right - 10
  draw.text((_right_x(brl(subtotal), font_h), box_y + 14), brl(subtotal), fill="black", font=font_h)

  draw.text((box_x + 16, box_y + 48), f"Frete{(' - ' + str(frete_nome)) if frete_nome else ''}", fill="black", font=font_h)
  draw.text((_right_x(brl(frete), font_h), box_y + 48), brl(frete), fill="black", font=font_h)

  # total destacado
  draw.rectangle([box_x, box_y + 78, box_x + box_w, box_y + 120], fill="#f1f5f9", outline="black", width=2)
  draw.text((box_x + 16, box_y + 88), "TOTAL GERAL", fill="black", font=font_total)
  draw.text((_right_x(brl(total_geral), font_total), box_y + 88), brl(total_geral), fill="black", font=font_total)

  # Observação de validade
  draw.text((margin, box_y + 140), f"Preços válidos até {valido_str} (10 dias).", fill="#333333", font=font_small)

  os.makedirs(os.path.join("static", "uploads"), exist_ok=True)
  out_path = os.path.join("static", "uploads", "orcamento.png")
  img.save(out_path, "PNG")
  return jsonify({"ok": True, "url": "/" + out_path.replace("\\", "/") + "?t=" + str(int(time.time()))})



if __name__ == "__main__":
  port = int(os.environ.get("PORT", "6262"))
  app.run(host="0.0.0.0", port=port, debug=True)