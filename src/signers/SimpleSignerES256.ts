import { fromJose } from '../util'
import { Signer } from '../JWT'
import { ES256Signer } from './ES256Signer'

/**
 * @deprecated Please use ES256Signer
 *  The SimpleSigner returns a configured function for signing data.
 *
 *  @example
 *  const signer = SimpleSigner(process.env.PRIVATE_KEY)
 *  signer(data, (err, signature) => {
 *    ...
 *  })
 *
 *  @param    {String}         hexPrivateKey    a hex encoded private key
 *  @return   {Function}                     a configured signer function
 */
function SimpleSignerES256(hexPrivateKey: string): Signer {
  const signer = ES256Signer(hexPrivateKey, true)
  return async (data) => {
    const signature = (await signer(data)) as string
    return fromJose(signature)
  }
}

export default SimpleSignerES256
