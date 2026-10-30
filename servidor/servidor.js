// ============================================================================
//  servidor.js  -  API REST del servicio de cifrado
//  CIB-204 Seguridad del Software - Universidad Cenfotec
//  >>> VERSION INSEGURA (rama inseguro) <<<
//
//  Endpoints:
//    GET  /salud       -> estado del servicio
//    GET  /llave       -> entrega la llave publica
//    POST /cifrar      -> cifra un texto
//    POST /descifrar   -> descifra un texto
//    GET  /buscar      -> consulta la bitacora (demostracion de SQLi)
//    POST /calcular    -> "utilidad" de calculo (demostracion de eval)
//    GET  /diagnostico -> ejecuta un ping (demostracion de command injection)
// ============================================================================

const express = require('express');
app.use(cors())
const cors = require('cors');
const { execFile } = require('child_process');
const cifrado = require('./cifrado');
const db = require('./db');
const config = require('./config');
const { requiereAuth } = require('./auth');
// Justificación: la API usa JWT en el header Authorization, sin cookies de sesión; CSRF no aplica.
// nosemgrep: javascript.express.security.audit.express-check-csurf-middleware-usage.express-check-csurf-middleware-usage
const app = express();

app.use(express.json());

// [VULN-5] CORS totalmente abierto: cualquier origen puede consumir la API.
//   Lo reporta OWASP ZAP (DAST) y Semgrep. La solucion es restringir a los
//   origenes de confianza.  CWE-942 (Overly Permissive CORS)

const helmet = require('helmet');
app.use(helmet());
app.use(cors({ origin: config.ORIGEN_PERMITIDO }));

// [VULN-6] Faltan cabeceras de seguridad (no se usa Helmet):
//   sin Content-Security-Policy, X-Content-Type-Options, etc.
//   Lo reporta OWASP ZAP.  CWE-693 (Protection Mechanism Failure)
//   (La solucion es: app.use(require('helmet')()).)

// El servicio genera su par de llaves al arrancar.
const llaves = cifrado.generarLlaves();

app.get('/salud', (req, res) => {
  res.json({ estado: 'ok', version: 'inseguro-1.0' });
});

app.get('/llave', (req, res) => {
  res.json({ llavePublica: llaves.publicKey });
});

app.post('/cifrar', requiereAuth, (req, res) => {
  const texto = req.body.texto;
  if (typeof texto !== 'string' || texto.length < 1 || texto.length > 180) {
    return res.status(400).json({ error: 'Texto invalido (1 a 180 caracteres)' });
  }
  try {
    const resultado = cifrado.cifrar(texto, llaves.publicKey);
    res.json({ cifrado: resultado });
  } catch (e) {
    res.status(500).json({ error: 'Error al cifrar' });
  }
});

app.post('/descifrar', requiereAuth, (req, res) => {
  const cifradoTxt = req.body.cifrado;
  if (typeof cifradoTxt !== 'string' || cifradoTxt.length < 1 || cifradoTxt.length > 1024) {
    return res.status(400).json({ error: 'Texto cifrado invalido' });
  }
  try {
    const resultado = cifrado.descifrar(cifradoTxt, llaves.privateKey);
    res.json({ descifrado: resultado });
  } catch (e) {
    res.status(500).json({ error: 'Error al descifrar' });
  }
});

// CORREGIDO Demostracion de INYECCION SQL (CWE-89).
app.get('/buscar', (req, res) => {
  const nombre = req.query.nombre || '';
  db.buscarBitacora(nombre, (err, data) => {
    res.json(data);
  });
});

// [VULN-9] Uso de eval() sobre entrada del usuario: inyeccion de codigo.
//   Lo detectan Semgrep y CodeQL (js/code-injection).
//   CWE-95 (Eval Injection)
app.post('/calcular', (req, res) => {
  const expresion = req.body.expresion || '0';
  try {
    //Modificado Fanny Redondo. const resultado = eval(expresion);
    //res.json({ resultado });
  const nums = Array.isArray(req.body.numeros) ? req.body.numeros : [];
  if (!nums.every(n => typeof n === 'number')) 
    return res.status(400).json({ error: 'Entrada invalida' });
  res.json({ resultado: nums.reduce((a,b)=>a+b,0) });
  
  } catch (e) {
    res.status(400).json({ error: 'Expresion invalida' });
  }
});

// Modif Fanny Redondo [VULN-10] CORREGIDO: inyeccion de comandos (CWE-78).
app.get('/diagnostico', (req, res) => {
  const host = String(req.query.host || '127.0.0.1');
  if (!/^[a-zA-Z0-9][a-zA-Z0-9.-]{0,63}$/.test(host)) {
    return res.status(400).json({ error: 'Host invalido' });
  }
  execFile('ping', ['-c', '1', host], { timeout: 5000 }, (err, stdout) => {
    if (err) return res.status(502).json({ error: 'No se pudo hacer ping al host' });
    res.json({ salida: stdout });
  });
});

if (require.main === module) {
  app.listen(config.PUERTO, () => {
    console.log('Servicio de cifrado escuchando en el puerto ' + config.PUERTO);
    console.log('AUTH_ENABLED =', config.AUTH_ENABLED);
  });
}

module.exports = app;
