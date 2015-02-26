package insure

/*
 * This package will implement an insurance policy for the coco collective
 * consensus signing protocol.
 *
 * In order to achieve a more scalable Dissent, it is important that the
 * protocol is able to make progress even in the midst of server failure.
 *
 * To accomplish this, servers will have to take out an "insurance policy".
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
 * This prelimary documentation will be updated as progress is made.
 *
 * DISCLAIMER: Life Policy is a work in progress. It's interface will change.
 * Please contact WEB3-GForce before using this code.
 */
