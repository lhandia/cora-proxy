// ═══════════════════════ RTC (REFORMA TRIBUTÁRIA) PROXY ═══════════════════════
// Ponte entre o Arcarius e a Calculadora oficial da Receita Federal (regime geral),
// publicada como um serviço Java separado (sem domínio público).
// O Arcarius envia o payload próprio dele; este módulo traduz para o contrato
// oficial, chama o serviço pela rede interna do Railway e devolve o resultado
// no formato que o Arcarius já normaliza.

const crypto = require('crypto');

module.exports = function criarRtcProxy({ apiKey } = {}) {
  const BASE = (process.env.RTC_CALCULADORA_URL || '').replace(/\/$/, '');
  const ROTA = process.env.RTC_CALCULADORA_PATH || '/api/calculadora/regime-geral';
  const ALIQUOTAS = process.env.RTC_ALIQUOTAS_NOMINAIS || '';
  const KEY = apiKey || process.env.RTC_PROXY_API_KEY || '';

  const num = (v) => {
    const n = Number(String(v === undefined || v === null ? '' : v).replace(',', '.'));
    return Number.isFinite(n) ? n : 0;
  };
  const arred = (n, casas = 2) => Number(Number(n).toFixed(casas));
  const digitos = (v) => String(v || '').replace(/\D/g, '');

  /** Traduz o payload do Arcarius para o contrato oficial da calculadora. */
  function montarOperacao(entrada) {
    const empresa = (entrada && entrada.empresa) || {};
    const operacao = (entrada && entrada.operacao) || {};
    const tributacao = (entrada && entrada.tributacao) || {};

    const data = String(operacao.data || '').slice(0, 10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(data)) return { erro: 'Data da operação inválida ou não informada.' };

    const municipio = digitos(operacao.municipio_incidencia || empresa.municipio_incidencia);
    if (municipio.length !== 7) return { erro: 'Município de incidência (código IBGE de 7 dígitos) não cadastrado na empresa.' };

    const uf = String(empresa.uf || operacao.destinatario_uf || '').toUpperCase().slice(0, 2);
    if (uf.length !== 2) return { erro: 'UF da empresa não cadastrada.' };

    if (!tributacao.cst) return { erro: 'CST de IBS/CBS não informado.' };
    if (!tributacao.cClassTrib) return { erro: 'cClassTrib não informado.' };

    const item = {
      numero: 1,
      cst: String(tributacao.cst),
      cClassTrib: String(tributacao.cClassTrib),
      baseCalculo: arred(num(operacao.valor)),
    };

    if (String(operacao.tipo || 'servico') === 'servico') {
      const nbs = digitos(tributacao.nbs);
      if (!nbs) return { erro: 'Código NBS não informado para operação de serviço.' };
      item.nbs = nbs;
    } else {
      const ncm = digitos(tributacao.ncm);
      if (!ncm) return { erro: 'Código NCM não informado para operação com mercadoria.' };
      item.ncm = ncm;
      item.quantidade = 1;
      item.unidade = 'UN';
    }

    // A partir de 2027 a API oficial exige as alíquotas nominais; antes disso, proíbe.
    if (Number(data.slice(0, 4)) >= 2027) {
      let aliquotas = null;
      try { aliquotas = ALIQUOTAS ? JSON.parse(ALIQUOTAS) : null; } catch (e) { aliquotas = null; }
      if (!aliquotas) return { erro: 'A partir de 2027 a calculadora oficial exige as alíquotas nominais (configure RTC_ALIQUOTAS_NOMINAIS).' };
      item.aliquotasNominais = aliquotas;
    }

    return {
      operacao: {
        id: crypto.createHash('md5').update(JSON.stringify(item) + data).digest('hex'),
        versao: '1.0.0',
        dhFatoGerador: data + 'T12:00:00-03:00',
        municipio: Number(municipio),
        uf: uf,
        itens: [item],
      },
    };
  }

  /** Converte a resposta oficial para o formato plano que o Arcarius já consome. */
  function mapearResposta(corpo) {
    const objetos = Array.isArray(corpo && corpo.objetos) ? corpo.objetos : (corpo && corpo.tribCalc ? [corpo] : []);
    const total = (corpo && corpo.total && corpo.total.tribCalc) || null;

    const erros = [];
    const memorias = [];
    let vBc = 0, vIbs = 0, vIbsUf = 0, vIbsMun = 0, vCbs = 0, vIs = 0;
    let aIbsUf = 0, aIbsMun = 0, aCbs = 0;

    for (const item of objetos) {
      const estado = item && item.estadoItem;
      if (estado && ['CALCULADO', 'CALCULO_SIMULADO'].indexOf(estado) === -1) {
        for (const e of (item.erros || [])) {
          erros.push(String((e.code || '') + ' ' + (e.title || '') + (e.detail ? ': ' + e.detail : '')).trim());
        }
      }

      const ibsCbs = item && item.tribCalc && item.tribCalc.IBSCBS;
      const g = ibsCbs && ibsCbs.gIBSCBS;
      if (g) {
        vBc += num(g.vBC);
        vIbs += num(g.vIBS);
        vIbsUf += num(g.gIBSUF && g.gIBSUF.vIBSUF);
        vIbsMun += num(g.gIBSMun && g.gIBSMun.vIBSMun);
        vCbs += num(g.gCBS && g.gCBS.vCBS);
        const ufRed = g.gIBSUF && g.gIBSUF.gRed ? g.gIBSUF.gRed.pAliqEfet : (g.gIBSUF ? g.gIBSUF.pIBSUF : undefined);
        const munRed = g.gIBSMun && g.gIBSMun.gRed ? g.gIBSMun.gRed.pAliqEfet : (g.gIBSMun ? g.gIBSMun.pIBSMun : undefined);
        const cbsRed = g.gCBS && g.gCBS.gRed ? g.gCBS.gRed.pAliqEfet : (g.gCBS ? g.gCBS.pCBS : undefined);
        aIbsUf = Math.max(aIbsUf, num(ufRed));
        aIbsMun = Math.max(aIbsMun, num(munRed));
        aCbs = Math.max(aCbs, num(cbsRed));
      }
      const isItem = item && item.tribCalc && item.tribCalc.IS;
      vIs += num(isItem ? ((isItem.gIS && isItem.gIS.vIS) !== undefined ? isItem.gIS.vIS : isItem.vIS) : 0);

      const mem = (ibsCbs && ibsCbs.memoriaCalculo) || (item && item.memoriaCalculo);
      if (mem) memorias.push(String(mem));
    }

    if (total) {
      const t = total.IBSCBSTot || {};
      if (t.vBCIBSCBS !== undefined) vBc = num(t.vBCIBSCBS);
      if (t.gIBS && t.gIBS.vIBS !== undefined) vIbs = num(t.gIBS.vIBS);
      if (t.gCBS && t.gCBS.vCBS !== undefined) vCbs = num(t.gCBS.vCBS);
      if (total.ISTot && total.ISTot.vIS !== undefined) vIs = num(total.ISTot.vIS);
    }

    return {
      base_calculo: arred(vBc),
      valor_ibs: arred(vIbs),
      valor_ibs_estadual: arred(vIbsUf),
      valor_ibs_municipal: arred(vIbsMun),
      valor_cbs: arred(vCbs),
      valor_is: arred(vIs),
      aliquota_ibs: arred(aIbsUf + aIbsMun, 4),
      aliquota_cbs: arred(aCbs, 4),
      memoria_calculo: memorias.join('\n\n'),
      fundamentacao: '',
      versao: 'calculadora-rtc-receita',
      versao_tabelas: '',
      erros: erros,
      bruto: corpo,
    };
  }

  async function handleRtcProxy(payload) {
    if (!BASE) return { status: 503, data: { error: 'Calculadora oficial não configurada (defina RTC_CALCULADORA_URL no Railway).' } };

    const montada = montarOperacao(payload);
    if (montada.erro) return { status: 400, data: { error: montada.erro } };

    const rota = ROTA.charAt(0) === '/' ? ROTA : '/' + ROTA;

    let resposta;
    try {
      resposta = await fetch(BASE + rota, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(montada.operacao),
        signal: AbortSignal.timeout(25000),
      });
    } catch (e) {
      return { status: 502, data: { error: 'Falha ao alcançar a calculadora oficial: ' + e.message } };
    }

    const texto = await resposta.text();
    let corpo = null;
    try { corpo = texto ? JSON.parse(texto) : null; } catch (e) { corpo = null; }

    if (!resposta.ok) {
      return { status: 502, data: { error: 'Calculadora oficial respondeu ' + resposta.status, detalhe: corpo || String(texto).slice(0, 400) } };
    }
    if (!corpo) return { status: 502, data: { error: 'Resposta da calculadora oficial sem conteúdo interpretável.' } };

    const mapeado = mapearResposta(corpo);
    const aviso = resposta.headers.get('x-warning-dados-simulados');
    if (aviso) mapeado.memoria_calculo = (aviso + '\n' + mapeado.memoria_calculo).trim();

    if (mapeado.erros.length && mapeado.valor_ibs === 0 && mapeado.valor_cbs === 0) {
      return { status: 422, data: { error: 'A calculadora oficial rejeitou a operação.', erros: mapeado.erros } };
    }
    delete mapeado.erros;
    return { status: 200, data: mapeado };
  }

  return { handleRtcProxy: handleRtcProxy, configurada: () => !!BASE, apiKey: KEY };
};
