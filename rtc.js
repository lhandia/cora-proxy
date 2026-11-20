// ═══════════════════════════════════════════════════════════════════════════
// REFORMA TRIBUTÁRIA — PONTE PARA AS CALCULADORAS OFICIAIS DA RECEITA FEDERAL
// ═══════════════════════════════════════════════════════════════════════════
// Duas calculadoras oficiais, publicadas como serviços Java separados (sem
// domínio público, alcançados pela rede do Railway):
//
//   /rtc-proxy          → regime regular (IBS/CBS/IS por operação)
//   /rtc-proxy-simples  → Simples Nacional (CBS/IBS por operação no Simples)
//
// O Arcarius envia o payload próprio dele; aqui ele é traduzido para o
// contrato oficial e a resposta volta no formato plano que o app normaliza.

const crypto = require('crypto');

const PROXY_API_KEY = process.env.PROXY_API_KEY || '';

const RTC_CALCULADORA_URL = (process.env.RTC_CALCULADORA_URL || '').replace(/\/$/, '');
const RTC_CALCULADORA_PATH = process.env.RTC_CALCULADORA_PATH || '/api/calculadora/regime-geral';
const RTC_PROXY_API_KEY = process.env.RTC_PROXY_API_KEY || PROXY_API_KEY;
// Alíquotas nominais exigidas pela API oficial a partir de 2027.
// Ex.: {"cbs":8.7,"ibsEstadual":0.05,"ibsMunicipal":0.05}
const RTC_ALIQUOTAS_NOMINAIS = process.env.RTC_ALIQUOTAS_NOMINAIS || '';

// Calculadora oficial do Simples Nacional (CBS/IBS por operação no Simples).
// O endpoint clássico aceita NF-e (55) e NFC-e (65) — NFS-e fica no motor interno.
const RTC_SIMPLES_URL = (process.env.RTC_CALCULADORA_SIMPLES_URL || '').replace(/\/$/, '');
const RTC_SIMPLES_PATH = process.env.RTC_CALCULADORA_SIMPLES_PATH || '/api/calculadora/observabilidade/simples-nacional';

const rtcNum = (v) => {
  const n = Number(String(v ?? '').replace(',', '.'));
  return Number.isFinite(n) ? n : 0;
};
const rtcArred = (n, casas = 2) => Number(Number(n).toFixed(casas));
const rtcDigitos = (v) => String(v || '').replace(/\D/g, '');

/** Traduz o payload do Arcarius para o contrato oficial da calculadora. */
function rtcMontarOperacao(entrada) {
  const empresa = entrada?.empresa || {};
  const operacao = entrada?.operacao || {};
  const tributacao = entrada?.tributacao || {};

  const data = String(operacao.data || '').slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(data)) {
    return { erro: 'Data da operação inválida ou não informada.' };
  }

  const municipio = rtcDigitos(operacao.municipio_incidencia || empresa.municipio_incidencia);
  if (municipio.length !== 7) {
    return { erro: 'Município de incidência (código IBGE de 7 dígitos) não cadastrado na empresa.' };
  }

  const uf = String(empresa.uf || operacao.destinatario_uf || '').toUpperCase().slice(0, 2);
  if (uf.length !== 2) return { erro: 'UF da empresa não cadastrada.' };

  if (!tributacao.cst) return { erro: 'CST de IBS/CBS não informado.' };
  if (!tributacao.cClassTrib) return { erro: 'cClassTrib não informado.' };

  const item = {
    numero: 1,
    cst: String(tributacao.cst),
    cClassTrib: String(tributacao.cClassTrib),
    baseCalculo: rtcArred(rtcNum(operacao.valor)),
  };

  if (String(operacao.tipo || 'servico') === 'servico') {
    const nbs = rtcDigitos(tributacao.nbs);
    if (!nbs) return { erro: 'Código NBS não informado para operação de serviço.' };
    item.nbs = nbs;
  } else {
    const ncm = rtcDigitos(tributacao.ncm);
    if (!ncm) return { erro: 'Código NCM não informado para operação com mercadoria.' };
    item.ncm = ncm;
    item.quantidade = 1;
    item.unidade = 'UN';
  }

  // A partir de 2027 a API oficial exige as alíquotas nominais; antes disso, proíbe.
  if (Number(data.slice(0, 4)) >= 2027) {
    let aliquotas = null;
    try {
      aliquotas = RTC_ALIQUOTAS_NOMINAIS ? JSON.parse(RTC_ALIQUOTAS_NOMINAIS) : null;
    } catch {
      aliquotas = null;
    }
    if (!aliquotas) {
      return { erro: 'A partir de 2027 a calculadora oficial exige as alíquotas nominais (configure RTC_ALIQUOTAS_NOMINAIS).' };
    }
    item.aliquotasNominais = aliquotas;
  }

  return {
    operacao: {
      id: crypto.createHash('md5').update(JSON.stringify(item) + data).digest('hex'),
      versao: '1.0.0',
      dhFatoGerador: `${data}T12:00:00-03:00`,
      municipio: Number(municipio),
      uf,
      itens: [item],
    },
  };
}

/** Converte a resposta oficial para o formato plano que o Arcarius já consome. */
function rtcMapearResposta(corpo) {
  const objetos = Array.isArray(corpo?.objetos) ? corpo.objetos : (corpo?.tribCalc ? [corpo] : []);
  const total = corpo?.total?.tribCalc || null;

  const erros = [];
  const memorias = [];
  let vBc = 0, vIbs = 0, vIbsUf = 0, vIbsMun = 0, vCbs = 0, vIs = 0;
  let aIbsUf = 0, aIbsMun = 0, aCbs = 0;

  for (const item of objetos) {
    const estado = item?.estadoItem;
    if (estado && !['CALCULADO', 'CALCULO_SIMULADO'].includes(estado)) {
      for (const e of (item.erros || [])) {
        erros.push(`${e.code || ''} ${e.title || ''}${e.detail ? ': ' + e.detail : ''}`.trim());
      }
    }

    const ibsCbs = item?.tribCalc?.IBSCBS;
    const g = ibsCbs?.gIBSCBS;
    if (g) {
      vBc += rtcNum(g.vBC);
      vIbs += rtcNum(g.vIBS);
      vIbsUf += rtcNum(g.gIBSUF?.vIBSUF);
      vIbsMun += rtcNum(g.gIBSMun?.vIBSMun);
      vCbs += rtcNum(g.gCBS?.vCBS);
      aIbsUf = Math.max(aIbsUf, rtcNum(g.gIBSUF?.gRed?.pAliqEfet ?? g.gIBSUF?.pIBSUF));
      aIbsMun = Math.max(aIbsMun, rtcNum(g.gIBSMun?.gRed?.pAliqEfet ?? g.gIBSMun?.pIBSMun));
      aCbs = Math.max(aCbs, rtcNum(g.gCBS?.gRed?.pAliqEfet ?? g.gCBS?.pCBS));
    }
    vIs += rtcNum(item?.tribCalc?.IS?.gIS?.vIS ?? item?.tribCalc?.IS?.vIS);

    const mem = ibsCbs?.memoriaCalculo || item?.memoriaCalculo;
    if (mem) memorias.push(String(mem));
  }

  // Os totais oficiais têm precedência sobre a soma dos itens.
  if (total) {
    const t = total.IBSCBSTot || {};
    if (t.vBCIBSCBS !== undefined) vBc = rtcNum(t.vBCIBSCBS);
    if (t.gIBS?.vIBS !== undefined) vIbs = rtcNum(t.gIBS.vIBS);
    if (t.gCBS?.vCBS !== undefined) vCbs = rtcNum(t.gCBS.vCBS);
    if (total.ISTot?.vIS !== undefined) vIs = rtcNum(total.ISTot.vIS);
  }

  return {
    base_calculo: rtcArred(vBc),
    valor_ibs: rtcArred(vIbs),
    valor_ibs_estadual: rtcArred(vIbsUf),
    valor_ibs_municipal: rtcArred(vIbsMun),
    valor_cbs: rtcArred(vCbs),
    valor_is: rtcArred(vIs),
    aliquota_ibs: rtcArred(aIbsUf + aIbsMun, 4),
    aliquota_cbs: rtcArred(aCbs, 4),
    memoria_calculo: memorias.join('\n\n'),
    fundamentacao: '',
    versao: 'calculadora-rtc-receita',
    versao_tabelas: '',
    erros,
    bruto: corpo,
  };
}

async function handleRtcProxy(payload) {
  if (!RTC_CALCULADORA_URL) {
    return { status: 503, data: { error: 'Calculadora oficial não configurada (defina RTC_CALCULADORA_URL no Railway).' } };
  }

  const montada = rtcMontarOperacao(payload);
  if (montada.erro) return { status: 400, data: { error: montada.erro } };

  const rota = RTC_CALCULADORA_PATH.startsWith('/') ? RTC_CALCULADORA_PATH : '/' + RTC_CALCULADORA_PATH;
  const url = `${RTC_CALCULADORA_URL}${rota}`;

  let resposta;
  try {
    resposta = await fetch(url, {
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
  try { corpo = texto ? JSON.parse(texto) : null; } catch { corpo = null; }

  if (!resposta.ok) {
    return {
      status: 502,
      data: { error: `Calculadora oficial respondeu ${resposta.status}`, detalhe: corpo || String(texto).slice(0, 400) },
    };
  }
  if (!corpo) {
    return { status: 502, data: { error: 'Resposta da calculadora oficial sem conteúdo interpretável.' } };
  }

  const mapeado = rtcMapearResposta(corpo);
  const aviso = resposta.headers.get('x-warning-dados-simulados');
  if (aviso) mapeado.memoria_calculo = `${aviso}\n${mapeado.memoria_calculo}`.trim();

  if (mapeado.erros.length && mapeado.valor_ibs === 0 && mapeado.valor_cbs === 0) {
    return { status: 422, data: { error: 'A calculadora oficial rejeitou a operação.', erros: mapeado.erros } };
  }
  delete mapeado.erros;
  return { status: 200, data: mapeado };
}

// ─────────────────────────── SIMPLES NACIONAL ───────────────────────────────
// Contrato oficial: CRT, tpRegimeIBSCBS, tpDoc e, por item, cClassTrib (que
// resolve internamente o tpRBSN) + NCM/NBS + base. cAtivSN é opcional.

/** Traduz o payload do Arcarius para o contrato oficial do Simples. */
function rtcMontarOperacaoSimples(entrada) {
  const empresa = entrada?.empresa || {};
  const operacao = entrada?.operacao || {};
  const tributacao = entrada?.tributacao || {};

  const data = String(operacao.data || '').slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(data)) {
    return { erro: 'Data da operação inválida ou não informada.' };
  }
  if (!tributacao.cClassTrib) return { erro: 'cClassTrib não informado.' };

  const tipo = String(operacao.tipo || 'servico');
  const tpDoc = String(operacao.tp_doc || (tipo === 'servico' ? '91' : '55'));
  if (!['55', '65'].includes(tpDoc)) {
    return {
      erro: 'A calculadora oficial do Simples Nacional cobre NF-e (55) e NFC-e (65). Operações de serviço (NFS-e) seguem no motor interno do Arcarius.',
      sem_suporte: true,
    };
  }

  // O motor oficial exige a atividade do Simples e as alíquotas efetivas de
  // IBS/CBS da empresa; sem elas o item volta como NAO_CALCULADO.
  const cAtivSN = String(tributacao.cAtivSN || empresa.cAtivSN || '').trim();
  if (!cAtivSN) {
    return { erro: 'Atividade do Simples (cAtivSN) não informada. Cadastre no enquadramento da empresa.' };
  }
  const pIBSSN = rtcNum(tributacao.pIBSSN ?? empresa.pIBSSN);
  const pCBSSN = rtcNum(tributacao.pCBSSN ?? empresa.pCBSSN);
  if (!pIBSSN && !pCBSSN) {
    return { erro: 'Alíquotas efetivas de IBS e CBS do Simples não informadas. Cadastre no enquadramento da empresa.' };
  }

  const item = {
    numero: 1,
    cAtivSN: cAtivSN.padStart(2, '0'),
    cClassTrib: String(tributacao.cClassTrib),
    baseCalculo: rtcArred(rtcNum(operacao.valor)),
    valorImpostoSeletivo: rtcArred(rtcNum(operacao.valor_is)),
    pIBSSN,
    pCBSSN,
  };
  // Mercadoria usa NCM; serviço usa NBS — enviar os dois no mesmo item é inconsistência.
  if (tipo === 'servico') {
    const nbs = rtcDigitos(tributacao.nbs);
    if (nbs) item.nbs = nbs;
  } else {
    const ncm = rtcDigitos(tributacao.ncm);
    if (ncm) item.ncm = ncm;
  }

  const oficial = {
    id: crypto.createHash('md5').update(JSON.stringify(item) + data + tpDoc).digest('hex'),
    versao: '2.0.0',
    data,
    tpDoc,
    CRT: String(empresa.crt || operacao.crt || '1'),
    itens: [item],
  };
  if (empresa.tpRegimeIBSCBS) oficial.tpRegimeIBSCBS = String(empresa.tpRegimeIBSCBS);
  if (empresa.tpEnteGov) oficial.tpEnteGov = String(empresa.tpEnteGov);

  return { operacao: oficial };
}

/** Converte a resposta do Simples para o formato plano do Arcarius. */
function rtcMapearRespostaSimples(corpo) {
  const objetos = Array.isArray(corpo?.objetos) ? corpo.objetos : [];
  const total = corpo?.total || null;

  const erros = [];
  const memorias = [];
  let vBc = 0, vIbs = 0, vCbs = 0, vIs = 0, aIbs = 0, aCbs = 0;

  for (const obj of objetos) {
    if (obj?.estadoItem && obj.estadoItem !== 'CALCULADO') {
      const motivo = obj?.motivoEstado?.descricao || obj?.motivoEstado?.motivo;
      if (motivo) erros.push(String(motivo));
      for (const e of (obj.erros || [])) {
        erros.push(`${e.code || ''} ${e.title || ''}${e.detail ? ': ' + e.detail : ''}`.trim());
      }
    }

    const t = obj?.tribCalc;
    if (!t) continue;
    vBc += rtcNum(t.vBC);
    vIbs += rtcNum(t.vIBSSN);
    vCbs += rtcNum(t.vCBSSN);
    vIs += rtcNum(t?.IS?.vIS ?? t?.IS?.valor ?? 0);
    aIbs = Math.max(aIbs, rtcNum(t.pIBSSN));
    aCbs = Math.max(aCbs, rtcNum(t.pCBSSN));

    const mem = t.memoriaCalculo;
    if (mem) {
      const partes = [mem.ibs, mem.cbs].filter(Boolean).join('\n');
      if (partes) memorias.push(partes);
    }
  }

  if (total) {
    if (total.vBC !== undefined) vBc = rtcNum(total.vBC);
    if (total.vIBSSNtot !== undefined) vIbs = rtcNum(total.vIBSSNtot);
    if (total.vCBSSNtot !== undefined) vCbs = rtcNum(total.vCBSSNtot);
    if (total.totalIs !== undefined) vIs = rtcNum(total.totalIs);
  }

  return {
    base_calculo: rtcArred(vBc),
    valor_ibs: rtcArred(vIbs),
    valor_ibs_estadual: 0,
    valor_ibs_municipal: 0,
    valor_cbs: rtcArred(vCbs),
    valor_is: rtcArred(vIs),
    aliquota_ibs: rtcArred(aIbs, 4),
    aliquota_cbs: rtcArred(aCbs, 4),
    memoria_calculo: memorias.join('\n\n'),
    fundamentacao: '',
    versao: 'calculadora-rtc-simples-nacional',
    versao_tabelas: '',
    erros,
    bruto: corpo,
  };
}

async function handleRtcProxySimples(payload) {
  if (!RTC_SIMPLES_URL) {
    return { status: 503, data: { error: 'Calculadora do Simples Nacional não configurada (defina RTC_CALCULADORA_SIMPLES_URL no Railway).' } };
  }

  const montada = rtcMontarOperacaoSimples(payload);
  if (montada.erro) return { status: montada.sem_suporte ? 501 : 400, data: { error: montada.erro } };

  const rota = RTC_SIMPLES_PATH.startsWith('/') ? RTC_SIMPLES_PATH : '/' + RTC_SIMPLES_PATH;
  const url = `${RTC_SIMPLES_URL}${rota}`;

  let resposta;
  try {
    resposta = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(montada.operacao),
      signal: AbortSignal.timeout(25000),
    });
  } catch (e) {
    return { status: 502, data: { error: 'Falha ao alcançar a calculadora do Simples: ' + e.message } };
  }

  const texto = await resposta.text();
  let corpo = null;
  try { corpo = texto ? JSON.parse(texto) : null; } catch { corpo = null; }

  if (!resposta.ok) {
    const detalhe = corpo?.detail || corpo?.title || corpo?.error || String(texto).slice(0, 300);
    return { status: 422, data: { error: `Calculadora do Simples respondeu ${resposta.status}`, detalhe } };
  }
  if (!corpo) {
    return { status: 502, data: { error: 'Resposta da calculadora do Simples sem conteúdo interpretável.' } };
  }

  const mapeado = rtcMapearRespostaSimples(corpo);
  if (mapeado.erros.length && mapeado.valor_ibs === 0 && mapeado.valor_cbs === 0) {
    return { status: 422, data: { error: 'A calculadora do Simples não calculou a operação.', erros: mapeado.erros } };
  }
  delete mapeado.erros;
  return { status: 200, data: mapeado };
}

function rtcStatus() {
  return {
    regime_regular_configurado: !!RTC_CALCULADORA_URL,
    simples_nacional_configurado: !!RTC_SIMPLES_URL,
  };
}

module.exports = { handleRtcProxy, handleRtcProxySimples, rtcStatus, RTC_PROXY_API_KEY };