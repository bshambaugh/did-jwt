import { ec as EC, SignatureInput } from 'elliptic'
import { sha256, toEthereumAddress } from '../Digest'
import type { VerificationMethod } from 'did-resolver'
import { bytesToHex, EcdsaSignature } from '../util'
import { verifyBlockchainAccountId } from '../blockchains'

import * as common_VerifierAlg from './common_VerifierAlg'

const secp256r1 = new EC('p256')

/*
interface LegacyVerificationMethod extends VerificationMethod {
  publicKeyBase64: string
}
*/

export function verifyES256(
  data: string,
  signature: string,
  authenticators: VerificationMethod[]
): VerificationMethod {
  const hash: Uint8Array = sha256(data)
  const sigObj: EcdsaSignature = common_VerifierAlg.toSignatureObject(signature)
  const fullPublicKeys = authenticators.filter(({ ethereumAddress, blockchainAccountId }) => {
    return typeof ethereumAddress === 'undefined' && typeof blockchainAccountId === 'undefined'
  })
  const blockchainAddressKeys = authenticators.filter(({ ethereumAddress, blockchainAccountId }) => {
    return typeof ethereumAddress !== 'undefined' || typeof blockchainAccountId !== 'undefined'
  })

  let signer: VerificationMethod | undefined = fullPublicKeys.find((pk: VerificationMethod) => {
    try {
      const pubBytes = common_VerifierAlg.extractPublicKeyBytes(pk)
      return secp256r1.keyFromPublic(pubBytes).verify(hash, <SignatureInput>sigObj)
    } catch (err) {
      return false
    }
  })

  if (!signer && blockchainAddressKeys.length > 0) {
    signer = verifyRecoverableES256(data, signature, blockchainAddressKeys)
  }

  if (!signer) throw new Error('invalid_signature: Signature invalid for JWT')
  return signer
}

export function verifyRecoverableES256(
  data: string,
  signature: string,
  authenticators: VerificationMethod[]
): VerificationMethod {
  let signatures: EcdsaSignature[]
  if (signature.length > 86) {
    signatures = [common_VerifierAlg.toSignatureObject(signature, true)]
  } else {
    const so = common_VerifierAlg.toSignatureObject(signature, false)
    signatures = [
      { ...so, recoveryParam: 0 },
      { ...so, recoveryParam: 1 },
    ]
  }

  const checkSignatureAgainstSigner = (sigObj: EcdsaSignature): VerificationMethod | undefined => {
    const hash: Uint8Array = sha256(data)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const recoveredKey: any = secp256r1.recoverPubKey(hash, <SignatureInput>sigObj, <number>sigObj.recoveryParam)
    const recoveredPublicKeyHex: string = recoveredKey.encode('hex')
    const recoveredCompressedPublicKeyHex: string = recoveredKey.encode('hex', true)
    const recoveredAddress: string = toEthereumAddress(recoveredPublicKeyHex)

    const signer: VerificationMethod | undefined = authenticators.find((pk: VerificationMethod) => {
      const keyHex = bytesToHex(common_VerifierAlg.extractPublicKeyBytes(pk))
      return (
        keyHex === recoveredPublicKeyHex ||
        keyHex === recoveredCompressedPublicKeyHex ||
        pk.ethereumAddress?.toLowerCase() === recoveredAddress ||
        pk.blockchainAccountId?.split('@eip155')?.[0].toLowerCase() === recoveredAddress || // CAIP-2
        verifyBlockchainAccountId(recoveredPublicKeyHex, pk.blockchainAccountId) // CAIP-10
      )
    })

    return signer
  }

  const signer: VerificationMethod[] = signatures
    .map(checkSignatureAgainstSigner)
    .filter((key) => typeof key !== 'undefined') as VerificationMethod[]

  if (signer.length === 0) throw new Error('invalid_signature: Signature invalid for JWT')
  return signer[0]
}
