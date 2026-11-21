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
const RTC_SIMPLES_PATH = process.env.RTC_CALCULADORA_SIMPLES_PATH || '/api/calculadora/observabilidade/simples-nacional/nao-assistido';

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
    if (mem) memorias.push(typeof mem === 'string' ? mem : JSON.stringify(mem));
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
      data: {
        error: `Calculadora oficial respondeu ${resposta.status}`,
        calculadora_http: resposta.status,
        calculadora_rota: rota,
        detalhe: corpo || String(texto).slice(0, 400),
      },
    };
  }
  if (!corpo) {
    return { status: 502, data: { error: 'Resposta da calculadora oficial sem conteúdo interpretável.', calculadora_http: resposta.status, calculadora_rota: rota } };
  }

  const mapeado = rtcMapearResposta(corpo);
  const aviso = resposta.headers.get('x-warning-dados-simulados');
  // Metadado verificável do trecho proxy → calculadora oficial.
  mapeado.meta = {
    calculadora_http: resposta.status,
    calculadora_rota: rota,
    aviso_simulado: aviso || '',
    recebido_em: new Date().toISOString(),
  };
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

// Contrato oficial vigente (v3.0.0): a linha de alíquotas efetivas do
// contribuinte vai na OPERAÇÃO, por anexo (aliquotasEfetivas.anexoX), e não
// mais por item. O endpoint clássico está marcado como OBSOLETO no Swagger.
const ANEXOS_SIMPLES = { I: 'anexoI', II: 'anexoII', III: 'anexoIII', IV: 'anexoIV', V: 'anexoV' };

// Documentos aceitos pelo motor oficial do Simples. A NFS-e (91) usa o mesmo
// endpoint, com o vocabulário do próprio documento (opSimpNac / regApTribSN) e
// os fatos do ISSQN no item.
const TPDOC_SIMPLES = ['55', '65', '91'];

// Atividades do Simples com ISS na base: exigem tribISSQN (VSN-036) e, quando a
// operação é tributável, tpRetISSQN (VSN-037). tpBM é opcional (VSN-038).
const ATIVIDADES_COM_ISS = ['07', '09', '10', '12', '13', '14'];

// A tabela vigente só parametriza tipo de documento a partir desta data.
const VIGENCIA_TABELA_SIMPLES = '2027-01-01';

const ROTULO_CAMPO = {
  opSimpNac: 'a opção pelo Simples (opSimpNac)',
  regApIBSCBSSN: 'o regime de apuração do IBS/CBS no Simples (regApIBSCBSSN)',
  regApTribSN: 'o regime de apuração dos tributos no Simples (regApTribSN)',
  tribISSQN: 'a tributação do ISSQN (tribISSQN)',
  tpRetISSQN: 'a retenção do ISSQN (tpRetISSQN)',
  tpBM: 'o benefício municipal do ISSQN (tpBM)',
};

/** Mensagem única para os campos obrigatórios que faltam. */
function rtcMensagemPendentes(pendentes) {
  return `Informe ${pendentes.map((c) => ROTULO_CAMPO[c] || c).join('; ')}.`;
}

/** Traduz o payload do Arcarius para o contrato oficial do Simples (v3.0.0). */
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
  if (!TPDOC_SIMPLES.includes(tpDoc)) {
    return {
      erro: `O motor oficial do Simples Nacional não aceita o tipo de documento ${tpDoc}.`,
      sem_suporte: true,
    };
  }

  // Vigência: a tabela instalada não cobre tipo de documento antes de 2027.
  // A calculadora responde VSN-015 nesse caso; a checagem evita a chamada e
  // deixa o motivo explícito para a tela.
  if (data < VIGENCIA_TABELA_SIMPLES) {
    return {
      erro: `Cálculo oficial indisponível para esta data: a tabela vigente do motor do Simples não cobre o tipo de documento ${tpDoc} antes de 01/01/2027.`,
      fora_vigencia: true,
    };
  }

  // O motor oficial exige a atividade do Simples e as alíquotas efetivas de
  // IBS/CBS da empresa; sem elas a operação é rejeitada na validação global.
  const cAtivSN = String(tributacao.cAtivSN || empresa.cAtivSN || '').trim().padStart(2, '0');
  if (!cAtivSN || cAtivSN === '00') {
    return { erro: 'Atividade do Simples (cAtivSN) não informada. Cadastre no enquadramento da empresa.', campos_pendentes: ['cAtivSN'] };
  }
  const pIBSSN = rtcNum(tributacao.pIBSSN ?? empresa.pIBSSN);
  const pCBSSN = rtcNum(tributacao.pCBSSN ?? empresa.pCBSSN);
  if (!pIBSSN && !pCBSSN) {
    return { erro: 'Alíquotas efetivas de IBS e CBS do Simples não informadas. Cadastre no enquadramento da empresa.', campos_pendentes: ['pIBSSN', 'pCBSSN'] };
  }

  const anexo = String(empresa.anexo_simples || '').toUpperCase().replace(/[^IVX]/g, '');
  const chaveAnexo = ANEXOS_SIMPLES[anexo];
  if (!chaveAnexo) {
    return { erro: 'Anexo do Simples Nacional (I a V) não informado na empresa.', campos_pendentes: ['anexo_simples'] };
  }

  const ehNfse = tpDoc === '91';

  // NFS-e: o regime vem no vocabulário do documento e CRT/tpRegimeIBSCBS são
  // proibidos (VSN-033). opSimpNac é sempre obrigatório; com ME/EPP (3) ou
  // opção pendente (4) a calculadora também exige os dois regimes de apuração.
  let opSimpNac = '';
  let regApIBSCBSSN = '';
  let regApTribSN = '';
  if (ehNfse) {
    const pendentes = [];
    opSimpNac = String(tributacao.opSimpNac || empresa.opSimpNac || '').trim();
    if (!['1', '2', '3', '4'].includes(opSimpNac)) pendentes.push('opSimpNac');
    if (['3', '4'].includes(opSimpNac)) {
      regApIBSCBSSN = String(tributacao.regApIBSCBSSN || '').trim();
      regApTribSN = String(tributacao.regApTribSN || '').trim();
      if (!['1', '2', '3'].includes(regApIBSCBSSN)) pendentes.push('regApIBSCBSSN');
      if (!['1', '2', '3'].includes(regApTribSN)) pendentes.push('regApTribSN');
    }
    if (pendentes.length) {
      return { erro: `NFS-e: ${rtcMensagemPendentes(pendentes)}`, campos_pendentes: pendentes };
    }
  }

  const item = {
    numero: 1,
    cAtivSN,
    cClassTrib: String(tributacao.cClassTrib),
    baseCalculo: rtcNum(operacao.valor).toFixed(2),
  };
  // Mercadoria usa NCM; serviço usa NBS — enviar os dois no mesmo item é inconsistência.
  if (tipo === 'servico') {
    const nbs = rtcDigitos(tributacao.nbs);
    if (nbs) item.nbs = nbs;
  } else {
    const ncm = rtcDigitos(tributacao.ncm);
    if (ncm) item.ncm = ncm;
  }

  if (ehNfse) {
    // Fatos do ISSQN: só são enviados quando informados. Nada é preenchido por
    // padrão — a ausência vira campo pendente, não um valor arbitrário.
    const tribISSQN = String(tributacao.tribISSQN || '').trim();
    const tpRetISSQN = String(tributacao.tpRetISSQN || '').trim();
    const tpBM = String(tributacao.tpBM || '').trim();
    const pendentes = [];
    if (ATIVIDADES_COM_ISS.includes(cAtivSN)) {
      if (!['1', '2', '3', '4'].includes(tribISSQN)) pendentes.push('tribISSQN');
      if (tribISSQN === '1' && !['1', '2', '3'].includes(tpRetISSQN)) pendentes.push('tpRetISSQN');
    }
    if (tpBM && !['1', '2', '3', '4'].includes(tpBM)) pendentes.push('tpBM');
    if (pendentes.length) {
      return { erro: `NFS-e: ${rtcMensagemPendentes(pendentes)}`, campos_pendentes: pendentes };
    }
    if (tribISSQN) item.tribISSQN = tribISSQN;
    if (tpRetISSQN) item.tpRetISSQN = tpRetISSQN;
    if (tpBM) item.tpBM = tpBM;
  } else {
    // Documentos com CRT repassam o IS já calculado; a NFS-e não tem IS.
    item.valorImpostoSeletivo = rtcNum(operacao.valor_is).toFixed(2);
  }

  const oficial = {
    id: crypto.createHash('md5').update(JSON.stringify(item) + data + tpDoc).digest('hex'),
    versao: '3.0.0',
    data,
    tpDoc,
    aliquotasEfetivas: {
      fatorR: false,
      impedimentoSublimite: false,
      [chaveAnexo]: { pCBSSN: pCBSSN.toFixed(4), pIBSSN: pIBSSN.toFixed(4) },
    },
    itens: [item],
  };

  if (ehNfse) {
    oficial.opSimpNac = opSimpNac;
    if (regApIBSCBSSN) oficial.regApIBSCBSSN = regApIBSCBSSN;
    if (regApTribSN) oficial.regApTribSN = regApTribSN;
  } else {
    oficial.CRT = String(empresa.crt || operacao.crt || '1');
    if (empresa.tpRegimeIBSCBS) oficial.tpRegimeIBSCBS = String(empresa.tpRegimeIBSCBS);
  }
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
      const partes = [mem.ibs, mem.cbs]
        .filter(Boolean)
        .map((p) => (typeof p === 'string' ? p : JSON.stringify(p)))
        .join('\n');
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
  if (montada.erro) {
    if (montada.fora_vigencia) {
      return {
        status: 422,
        data: {
          error: montada.erro,
          codigo: 'FORA_VIGENCIA_TABELA',
          vigencia: {
            data_operacao: String(payload?.operacao?.data || '').slice(0, 10),
            data_minima: VIGENCIA_TABELA_SIMPLES,
          },
        },
      };
    }
    return {
      status: montada.sem_suporte ? 501 : 400,
      data: { error: montada.erro, campos_pendentes: montada.campos_pendentes || [] },
    };
  }

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
    return { status: 422, data: { error: `Calculadora do Simples respondeu ${resposta.status}`, calculadora_http: resposta.status, calculadora_rota: rota, detalhe } };
  }
  if (!corpo) {
    return { status: 502, data: { error: 'Resposta da calculadora do Simples sem conteúdo interpretável.' } };
  }

  const mapeado = rtcMapearRespostaSimples(corpo);
  // Metadado verificável do trecho proxy → calculadora oficial do Simples.
  mapeado.meta = {
    calculadora_http: resposta.status,
    calculadora_rota: rota,
    recebido_em: new Date().toISOString(),
  };
  if (mapeado.erros.length && mapeado.valor_ibs === 0 && mapeado.valor_cbs === 0) {
    return { status: 422, data: { error: 'A calculadora do Simples não calculou a operação.', calculadora_http: resposta.status, calculadora_rota: rota, erros: mapeado.erros, amostra: corpo } };
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