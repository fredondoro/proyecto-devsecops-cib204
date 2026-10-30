// ============================================================================
//  auth.js  -  Gestion de identidad y acceso (IAM)
//  Valida el token JWT contra el JWKS de Keycloak. Solo acepta RS256.
// ============================================================================

const { expressjwt } = require('express-jwt');
const jwksRsa = require('jwks-rsa');
const config = require('./config');

// CORREGIDO [VULN-4]: se valida la firma con la llave publica de Keycloak,
// se restringe el algoritmo a RS256 y no se acepta 'none' ni decode sin verificar.
// CWE-347 / CWE-287
const validarToken = expressjwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: config.JWKS_URI,
  }),
  algorithms: ['RS256'],
  requestProperty: 'usuario',
});

function requiereAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  console.log("Header recibido:", authHeader); // IMPRIME EL ENCABEZADO REAL

  if (!authHeader) {
    return res.status(401).json({ error: 'se requiere token' });
  }
  // Si el control de acceso esta apagado, deja pasar (solo para pruebas).
  if (!config.AUTH_ENABLED) {
    return next();
  }
  validarToken(req, res, (err) => {
    if (err) {
      return res.status(401).json({ error: 'No autorizado' });
    }
    next();
  });
}

module.exports = { requiereAuth };