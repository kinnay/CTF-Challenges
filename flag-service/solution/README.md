
The flaws in the challenge are:
* An insecure RNG is used to generate the nonce
* When multiple tickets are requested for an account, they are all encrypted with the same RC4 key

The basic idea behind the attack is as follows:
1. Register an account with a known password
2. Request multiple tickets for that account, decrypt the responses, and extract the nonces from the tickets
3. Use the nonces from step 2 to recover the RNG state
4. Request a ticket for Administrator for a service with a known password
5. Because the password of the service is known, and the nonce can be predicted, the content of the ticket can be predicted
6. Apply an XOR between the predicted ticket and the response from the server to recover the RC4 keystream of the Administrator account
7. Request a ticket for Administrator for the Flag Service
8. Decrypt the response using the keystream from step 6
9. The ticket of step 8 can be used to retrieve the flag

The attack is implemented in solve.py. The remaining Python files contain a modified version of the code from https://github.com/fx5/not_random. This repository implements code to reconstruct an MT19937 state when only part of each output value is known. The modifications port the repository to Python 3 and adjust it to use the correct bits.

To execute the attack, first execute rebuild_random.py to generate magic_data_8. This will take a while. Then, solve.py can be used to obtain the flag.
