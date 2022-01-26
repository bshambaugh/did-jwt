import SignerAlgorithm from '../../SignerAlgorithm'
import { toSignatureObject } from '../../VerifierAlgorithm'
//import SimpleSigner from '../../signers/SimpleSigner'
import SimpleSignerES256 from '../../signers/SimpleSignerES256'
// import EllipticSigner from '../../signers/EllipticSigner'
import EllipticSignerES256 from '../../signers/EllipticSignerES256'
import { ec as EC } from 'elliptic'
import { base64ToBytes, stringToBytes } from '../../util'
import { sha256 } from '../../Digest'
const secp256r1 = new EC('p256')
const privateKey = '9532c1aa21aad885b3fd1792d9e42dace4298f3aef6cfd60198ac9c563265c04'
const kp = secp256r1.keyFromPrivate(privateKey)
// simple signer uses ES256K (secp256k1)
const signer = SimpleSignerES256(privateKey)
//const signer = SimpleSigner(privateKey)
const ecSigner = EllipticSignerES256(privateKey)
// const ecSigner = EllipticSigner(privateKey)

var pubPoint = kp.getPublic();
var x = pubPoint.getX();
var y = pubPoint.getY();

var pub = { x: x.toString('hex'), y: y.toString('hex') };

describe('SignerAlgorithm', () => {
  it('supports ES256', () => {
    expect(typeof SignerAlgorithm('ES256')).toEqual('function')
  })

  it('supports ES256-R', () => {
    expect(typeof SignerAlgorithm('ES256-R')).toEqual('function')
  })

})

describe('ES256', () => {
  const jwtSigner = SignerAlgorithm('ES256')
  it('returns correct signature', async () => {
    expect.assertions(1)
    console.log(pub);
    return await expect(jwtSigner('hello', signer)).resolves.toEqual(
      '6SThI3deiVfadJJIIw2ZW-rU7CUzlNZ_BXLIw4BSTXwsxHm24p_ca2ZSwEKl4Xcdu6HQxVY-ENH4yJbpha64HQ'
    )
  })

  it('returns signature of 64 bytes', async () => {
    expect.assertions(1)
    const signature = await jwtSigner('hello', signer)
    expect(base64ToBytes(signature).length).toEqual(64)
  })

  it('contains only r and s of signature', async () => {
    expect.assertions(1)
    const signature = await jwtSigner('hello', signer)
    expect(toSignatureObject(signature)).toEqual({
      r: 'e924e123775e8957da749248230d995bead4ec253394d67f0572c8c380524d7c',
      s: '2cc479b6e29fdc6b6652c042a5e1771dbba1d0c5563e10d1f8c896e985aeb81d',
    })
  })

  it('can verify the signature', async () => {
    expect.assertions(1)
    const signature = await jwtSigner('hello', signer)
    expect(kp.verify(sha256('hello'), toSignatureObject(signature))).toBeTruthy()
  })
})

describe('ES256 signer which returns signature as string ', () => {
  const jwtSigner = SignerAlgorithm('ES256')
  it('returns correct signature', async () => {
    expect.assertions(1)
    return await expect(jwtSigner('hello', ecSigner)).resolves.toEqual(
      '6SThI3deiVfadJJIIw2ZW-rU7CUzlNZ_BXLIw4BSTXwsxHm24p_ca2ZSwEKl4Xcdu6HQxVY-ENH4yJbpha64HQ'
    )
  })

  it('returns signature of 64 bytes', async () => {
    expect.assertions(1)
    const signature = await jwtSigner('hello', ecSigner)
    expect(base64ToBytes(signature).length).toEqual(64)
  })

  it('can verify the signature', async () => {
    expect.assertions(1)
    const signature = await jwtSigner('hello', ecSigner)
    expect(kp.verify(sha256('hello'), toSignatureObject(signature))).toBeTruthy()
  })
})

describe('ES256-R', () => {
  const jwtSigner = SignerAlgorithm('ES256-R')
  expect.assertions(1)
  it('returns correct signature', async () => {
    return await expect(jwtSigner('hello', signer)).resolves.toEqual(
      '6SThI3deiVfadJJIIw2ZW-rU7CUzlNZ_BXLIw4BSTXwsxHm24p_ca2ZSwEKl4Xcdu6HQxVY-ENH4yJbpha64HQ'
    )
  })

  it('returns signature of 64 bytes', async () => {
    expect.assertions(1)
    const signature = await jwtSigner('hello', signer)
    expect(base64ToBytes(signature).length).toEqual(65)
  })

  it('contains r, s and recoveryParam of signature', async () => {
    expect.assertions(1)
    const signature = await jwtSigner('hello', signer)
    expect(toSignatureObject(signature, true)).toEqual({
      r: 'e924e123775e8957da749248230d995bead4ec253394d67f0572c8c380524d7c',
      s: '2cc479b6e29fdc6b6652c042a5e1771dbba1d0c5563e10d1f8c896e985aeb81d',
      recoveryParam: 1,
    })
  })

  it('can verify the signature', async () => {
    expect.assertions(1)
    const signature = await jwtSigner('hello', signer)
    expect(kp.verify(sha256('hello'), toSignatureObject(signature, true))).toBeTruthy()
  })
})
