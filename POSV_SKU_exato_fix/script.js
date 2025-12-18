// Estado em memória do carrinho
let carrinho = [];

// Util: formata número em BRL
function formatarBRL(valor) {
  const num = Number(valor || 0);
  return num.toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });
}

// Renderiza itens do carrinho
function renderizarCarrinho() {
  const container = document.getElementById('carrinho-itens');
  if (!container) return;

  if (!carrinho.length) {
    container.innerHTML = '<p class="muted">Nenhum item no carrinho.</p>';
  } else {
    container.innerHTML = carrinho
      .map(
        (item, idx) => `
      <div class="carrinho-item">
        <div class="carrinho-item-main">
          <div class="carrinho-item-header">
            <span class="carrinho-item-nome">${item.nome}</span>
            <span class="carrinho-item-preco">${formatarBRL(item.preco)}</span>
          </div>
          <div class="carrinho-item-subinfo">
            <span>SKU: ${item.sku || ''}</span>
            <span>Peso: ${item.peso ? Number(item.peso).toFixed(2) + ' kg' : ''}</span>
          </div>
        </div>
        <div class="carrinho-item-actions">
          <input type="number"
                 min="1"
                 value="${item.quantidade}"
                 data-idx="${idx}"
                 class="carrinho-qtd-input" />
          <button class="carrinho-remover" data-idx="${idx}">Remover</button>
        </div>
      </div>
    `
      )
      .join('');
  }

  atualizarTotais();
}

// Atualiza valores de totais
function atualizarTotais() {
  const totalProdutosEl = document.getElementById('total-produtos');
  const totalFreteEl = document.getElementById('total-frete');
  const totalGeralEl = document.getElementById('total-geral');

  let totalProdutos = 0;
  carrinho.forEach((item) => {
    totalProdutos += Number(item.preco) * Number(item.quantidade || 1);
  });

  const freteSelecionado =
    window.freteSelecionado && window.freteSelecionado.preco
      ? Number(window.freteSelecionado.preco)
      : 0;

  if (totalProdutosEl) totalProdutosEl.textContent = formatarBRL(totalProdutos);
  if (totalFreteEl) totalFreteEl.textContent = formatarBRL(freteSelecionado);
  if (totalGeralEl) totalGeralEl.textContent = formatarBRL(totalProdutos + freteSelecionado);
}

// Adiciona produto ao carrinho
function adicionarAoCarrinho(prod) {
  const existente = carrinho.find((p) => p.id === prod.id);
  const pesoParaFrete = prod.peso ? Number(prod.peso) : 0.5;

  if (existente) {
    existente.quantidade += 1;
    if (!existente.peso) existente.peso = pesoParaFrete;
  } else {
    carrinho.push({
      id: prod.id,
      nome: prod.nome,
      preco: prod.preco,
      sku: prod.sku || '',
      peso: pesoParaFrete,
      quantidade: 1,
    });
  }

  renderizarCarrinho();
  atualizarCamposPacote();
}

// Atualiza campos padrão de pacote com base no carrinho
function atualizarCamposPacote() {
  const larguraEl = document.getElementById('pacote-width');
  const alturaEl = document.getElementById('pacote-height');
  const comprimentoEl = document.getElementById('pacote-length');
  const pesoEl = document.getElementById('pacote-weight');
  const insuranceEl = document.getElementById('pacote-insurance');

  if (!larguraEl || !alturaEl || !comprimentoEl || !pesoEl || !insuranceEl) return;

  let pesoTotal = 0;
  let valorTotal = 0;

  carrinho.forEach((item) => {
    const qtd = Number(item.quantidade || 1);
    const pesoItem = item.peso ? Number(item.peso) : 0.5;
    pesoTotal += pesoItem * qtd;
    valorTotal += Number(item.preco) * qtd;
  });

  if (!pesoTotal) pesoTotal = 0.5;

  larguraEl.value = larguraEl.value || '11';
  alturaEl.value = alturaEl.value || '17';
  comprimentoEl.value = comprimentoEl.value || '11';
  pesoEl.value = pesoTotal.toFixed(2).replace('.', ',');
  insuranceEl.value = valorTotal.toFixed(2).replace('.', ',');
}

// Obtém pacotes a partir dos campos da tela
function obterPacotesDoFormulario() {
  const larguraEl = document.getElementById('pacote-width');
  const alturaEl = document.getElementById('pacote-height');
  const comprimentoEl = document.getElementById('pacote-length');
  const pesoEl = document.getElementById('pacote-weight');
  const insuranceEl = document.getElementById('pacote-insurance');

  if (!larguraEl || !alturaEl || !comprimentoEl || !pesoEl || !insuranceEl) return [];

  function parseCampo(el) {
    if (!el || !el.value) return 0;
    return Number(el.value.replace(',', '.'));
  }

  const largura = parseCampo(larguraEl);
  const altura = parseCampo(alturaEl);
  const comprimento = parseCampo(comprimentoEl);
  const peso = parseCampo(pesoEl);
  const insurance = parseCampo(insuranceEl);

  if (!largura || !altura || !comprimento || !peso) {
    return [];
  }

  return [
    {
      width: largura,
      height: altura,
      length: comprimento,
      weight: peso,
      insurance: insurance || 0,
    },
  ];
}

// Renderiza lista de produtos
function renderizarProdutos(lista, totalAtivos) {
  const container = document.getElementById('produtos-lista');
  if (!container) return;

  const infoTotal = document.getElementById('info-total-produtos');
  if (infoTotal && typeof totalAtivos === 'number') {
    infoTotal.textContent = `Produtos ativos carregados do Bling: ${totalAtivos}`;
  }

  if (!lista || !lista.length) {
    container.innerHTML = '<p class="muted">Nenhum produto encontrado para este termo.</p>';
    return;
  }

  container.innerHTML = lista
    .map((p) => {
      const precoStr = formatarBRL(p.preco);
      const skuStr = p.sku || '';
      const pesoStr =
        p.peso !== undefined && p.peso !== null && p.peso !== ''
          ? `${Number(p.peso).toFixed(2)} kg`
          : '';
      const estoqueStr = '—'; // placeholder para implementação futura

      let imagemHtml = '<span class="muted">Sem imagem</span>';
      if (p.imagem_url) {
        const safeUrl = String(p.imagem_url);
        imagemHtml = `<img src="${safeUrl}" alt="Imagem produto" onerror="this.style.display='none';" />`;
      }

      return `
      <article class="produto-card">
        <div class="produto-img-wrapper">
          ${imagemHtml}
        </div>
        <div class="produto-conteudo">
          <div class="produto-titulo">${p.nome}</div>
          <div class="produto-info">
            <div>SKU: ${skuStr}</div>
            <div>Estoque: ${estoqueStr}</div>
            <div>Peso: ${pesoStr}</div>
          </div>
          <div class="produto-preco">${precoStr}</div>
        </div>
        <div>
          <button class="btn btn-add-carrinho" data-id="${p.id}">Adicionar ao carrinho</button>
        </div>
      </article>
    `;
    })
    .join('');

  container.querySelectorAll('.btn-add-carrinho').forEach((btn) => {
    btn.addEventListener('click', () => {
      const id = btn.getAttribute('data-id');
      const produto = lista.find((p) => String(p.id) === String(id));
      if (produto) adicionarAoCarrinho(produto);
    });
  });
}

// Busca produtos via API
async function buscarProdutos(reload = false) {
  const termo = document.getElementById('busca-input').value || '';
  const params = new URLSearchParams();
  if (termo.trim()) params.set('busca', termo.trim());
  if (reload) params.set('reload', '1');

  const container = document.getElementById('produtos-lista');
  if (container) {
    container.innerHTML = '<p class="muted">Buscando produtos...</p>';
  }

  try {
    const resp = await fetch('/api/produtos?' + params.toString());
    const data = await resp.json();

    if (!resp.ok) {
      const msg = data && data.error ? data.error : 'Erro ao buscar produtos.';
      if (container) container.innerHTML = `<p class="erro-msg">${msg}</p>`;
      return;
    }

    renderizarProdutos(data.produtos || [], data.total_ativos);
  } catch (err) {
    if (container) {
      container.innerHTML = `<p class="erro-msg">Erro de comunicação ao buscar produtos: ${err}</p>`;
    }
  }
}

// Calcula frete
async function calcularFrete() {
  const cepDestinoEl = document.getElementById('cep-destino');
  const freteOpcoesEl = document.getElementById('frete-opcoes');
  if (!cepDestinoEl || !freteOpcoesEl) return;

  const cepDestino = (cepDestinoEl.value || '').replace(/\D/g, '');
  if (!cepDestino || cepDestino.length < 8) {
    freteOpcoesEl.innerHTML =
      '<p class="erro-msg">Informe um CEP de destino válido (8 dígitos).</p>';
    return;
  }

  const providerRadio = document.querySelector('input[name="frete-provider"]:checked');
  const provider = providerRadio ? providerRadio.value : 'melhorenvio';

  const packages = obterPacotesDoFormulario();
  if (!packages.length) {
    freteOpcoesEl.innerHTML =
      '<p class="erro-msg">Preencha os dados do pacote (largura, altura, comprimento, peso).</p>';
    return;
  }

  freteOpcoesEl.innerHTML = '<p class="muted">Calculando frete...</p>';

  try {
    const resp = await fetch('/api/calcular-frete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        provider,
        cep_destino: cepDestino,
        packages,
      }),
    });

    const data = await resp.json();
    if (!resp.ok) {
      const msg = data && data.error ? data.error : 'Erro ao calcular frete.';
      freteOpcoesEl.innerHTML = `<p class="erro-msg">${msg}</p>`;
      return;
    }

    const opcoes = data.opcoes || [];
    if (!opcoes.length) {
      freteOpcoesEl.innerHTML =
        '<p class="muted">Nenhuma opção de frete retornada para os dados informados.</p>';
      return;
    }

    freteOpcoesEl.innerHTML = opcoes
      .map(
        (opt, idx) => `
        <div class="frete-opcao">
          <input type="radio"
                 name="frete-opcao"
                 value="${idx}"
                 ${idx === 0 ? 'checked' : ''} />
          <label>
            <span class="frete-opcao-servico">${opt.nome || 'Serviço'}</span>
            <span class="frete-opcao-preco">${formatarBRL(opt.preco)}</span>
            <span class="frete-opcao-prazo">
              Prazo: ${
                opt.prazo && (opt.prazo.delivery_range || opt.prazo)
                  ? JSON.stringify(opt.prazo)
                  : 'não informado'
              }
            </span>
          </label>
        </div>
      `
      )
      .join('');

    window.freteSelecionado = opcoes[0] || null;
    atualizarTotais();

    freteOpcoesEl
      .querySelectorAll('input[name="frete-opcao"]')
      .forEach((radio, idx) => {
        radio.addEventListener('change', () => {
          window.freteSelecionado = opcoes[idx] || null;
          atualizarTotais();
        });
      });
  } catch (err) {
    freteOpcoesEl.innerHTML = `<p class="erro-msg">Erro de comunicação ao calcular frete: ${err}</p>`;
  }
}

// Inicialização
function registrarEventos() {
  const btnBuscar = document.getElementById('btn-buscar-produtos');
  if (btnBuscar) {
    btnBuscar.addEventListener('click', () => buscarProdutos(false));
  }

  const buscaInput = document.getElementById('busca-input');
  if (buscaInput) {
    buscaInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        buscarProdutos(false);
      }
    });
  }

  const btnAtualizarCache = document.getElementById('btn-atualizar-cache');
  if (btnAtualizarCache) {
    btnAtualizarCache.addEventListener('click', () => buscarProdutos(true));
  }

  const carrinhoContainer = document.getElementById('carrinho-itens');
  if (carrinhoContainer) {
    carrinhoContainer.addEventListener('change', (e) => {
      const target = e.target;
      if (target.classList.contains('carrinho-qtd-input')) {
        const idx = Number(target.getAttribute('data-idx'));
        const novaQtd = Math.max(1, Number(target.value || 1));
        if (!Number.isNaN(idx) && carrinho[idx]) {
          carrinho[idx].quantidade = novaQtd;
          atualizarCamposPacote();
          atualizarTotais();
        }
      }
    });

    carrinhoContainer.addEventListener('click', (e) => {
      const target = e.target;
      if (target.classList.contains('carrinho-remover')) {
        const idx = Number(target.getAttribute('data-idx'));
        if (!Number.isNaN(idx) && carrinho[idx]) {
          carrinho.splice(idx, 1);
          renderizarCarrinho();
          atualizarCamposPacote();
        }
      }
    });
  }

  const btnCalcularFrete = document.getElementById('btn-calcular-frete');
  if (btnCalcularFrete) {
    btnCalcularFrete.addEventListener('click', () => calcularFrete());
  }
}

document.addEventListener('DOMContentLoaded', () => {
  registrarEventos();
});
