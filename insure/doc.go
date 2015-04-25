/* This package implements the insurance policy protocol for coco collective
 * consensus signing.
 *
 * In order to achieve a more scalable Dissent, it is important that the
 * protocol is able to make progress even in the midst of server failure.
 *
 * To accomplish this, servers will have to take out an insurance (life) policy.
 * Servers will use Shamir Secret Sharing to give shares of their private keys
 * to n other servers who will act as insurers. Once the server has done so,
 * it can fully participate in the system and perform work for clients.
 *
 * In the event that a server becomes unresponsive, clients currently relying on
 * the server can contact insurers. Each insurer will then attempt to contact
 * the server. If the server responds with the desired work for the client, the
 * insurer will simply forward this to the client. Otherwise, it will give its
 * piece of the secret to the client. If the client is able to receive t of n
 * shares from the insurers, the client can recreate the private key of the
 * server and carry out the work itself.
 *
 * Please see lifePolicy.go for more information about the networking code. See
 * crypto/poly/promise.go for more about the cryptographic objects used.
 */
package insure
