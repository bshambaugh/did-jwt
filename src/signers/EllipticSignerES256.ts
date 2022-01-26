import { Signer } from '../JWT'
import { ES256Signer } from './ES256Signer'

/**
 * @deprecated Please use ES256KSigner
 *  The EllipticSigner returns a configured function for signing data.
 *
 *  @example
 *  ```typescript
 *  const signer = EllipticSigner(process.env.PRIVATE_KEY)
 *  signer(data).then( (signature: string) => {
 *    ...
 *  })
 *  ```
 *
 *  @param    {String}         hexPrivateKey    a hex encoded private key
 *  @return   {Function}                        a configured signer function
 */
function EllipticSignerES256(hexPrivateKey: string): Signer {
  return ES256Signer(hexPrivateKey)
}

export default EllipticSignerES256
