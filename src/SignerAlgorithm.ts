import { SignerAlgorithm } from './JWT'

import * as ES256KSignerAlg from './SignerAlg/ES256KSignerAlg'
import * as Ed25519SignerAlg from './SignerAlg/Ed25519SignerAlg'

import * as ES256SignerAlg from './SignerAlg/ES256SignerAlg'

interface SignerAlgorithms {
  [alg: string]: SignerAlgorithm
}

const algorithms: SignerAlgorithms = {
  ES256:  ES256SignerAlg.ES256SignerAlg(),
  ES256-R: ES256SignerAlg.ES256SignerAlg(true),
  ES256K: ES256KSignerAlg.ES256KSignerAlg(),
  // This is a non-standard algorithm but retained for backwards compatibility
  // see https://github.com/decentralized-identity/did-jwt/issues/146
  'ES256K-R': ES256KSignerAlg.ES256KSignerAlg(true),
  // This is actually incorrect but retained for backwards compatibility
  // see https://github.com/decentralized-identity/did-jwt/issues/130
  Ed25519: Ed25519SignerAlg.Ed25519SignerAlg(),
  EdDSA: Ed25519SignerAlg.Ed25519SignerAlg(),
}

function SignerAlg(alg: string): SignerAlgorithm {
  const impl: SignerAlgorithm = algorithms[alg]
  if (!impl) throw new Error(`not_supported: Unsupported algorithm ${alg}`)
  return impl
}

export default SignerAlg
