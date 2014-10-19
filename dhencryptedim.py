import getopt,sys,socket,select
from Crypto.Hash import SHA
from Crypto.Hash import HMAC
from Crypto import Random
from Crypto.Random.random import StrongRandom
from Crypto.Cipher import AES

#Allows two computers to connect to send/receive encrypted messages to/from each other

PORT_NUM = 9999
DH_G = 2
DH_P = 0x00cc81ea8157352a9e9a318aac4e33ffba80fc8da3373fb44895109e4c3ff6cedcc55c02228fccbd551a504feb4346d2aef47053311ceaba95f6c540b967b9409e9f0502e598cfc71327c5a455e2e807bede1e0b7d23fbea054b951ca964eaecae7ba842ba1fc6818c453bf19eb9c5c86e723e69a210d4b72561cab97b3fb3060b

try:
    def usage():
        #prints correct command line arguments
        print 'Usage: DHEncryptedIM [-s|-c hostname]'

    def get_args():
        #gets command line arguments syntax
        try:
            opts, args = getopt.getopt(sys.argv[1:], 'sc:')
        except getopt.GetoptError as err:
            print str(err)
            usage()
            sys.exit()

        for curr_opt, curr_arg in opts:
            if curr_opt == '-c':
                connection_type = 'client'
                hostname = curr_arg
            elif curr_opt == '-s':
                connection_type = 'server'
                hostname = None
        #if user input all arguments, return them. Else, print correct syntax and exit.
        if 'connection_type'in locals() and 'hostname' in locals():
            return connection_type, hostname
        else:
            usage()
            sys.exit()

    #sender generates secret 'a', calculates 'A', and sends to the other party
    def dh_send_generated_secret(s):
        #generates a random number up to DH_P
        r = StrongRandom()
        a = r.randint(0, DH_P)
        A = pow(DH_G, a, DH_P)
        s.send(str(A))
        return a

    #upon receiving "secret" 'B' from the other party, computes a hash of k
    def dh_process_received_secret(a, B):
        k = pow(long(B), a, DH_P)
        return hash_key(k)

    def hash_key(k):
        #calculate first 128 bits of hash of key k
        k_sha = SHA.new(str(k).encode())
        return k_sha.digest()[:16]

    def send_message(k_sha_digest_128, outputs_ready):

        #pads message until length is a multiple of 16
        msg_to_send = sys.stdin.readline()
        if k_sha_digest_128 is not None and len(outputs_ready) > 0:
            while len(msg_to_send) % AES.block_size != 0:
                msg_to_send += '\0'

            #create new cipher based on the hashed key k and a fresh IV
            iv = Random.new().read(AES.block_size)
            cipher = AES.new(k_sha_digest_128, AES.MODE_CBC, iv)

            #pads a string holding the length of the message until the string length is a multiple of 16
            msg_length = str(len(msg_to_send))
            while len(msg_length) % AES.block_size != 0:
                msg_length += '\0'

            #encrypts message and concatenates all pieces to send
            encrypted_msg_to_send = msg_length + iv + cipher.encrypt(msg_to_send)
            outputs_ready[0].send(encrypted_msg_to_send)
        else:
            #connection was never initiated or was disconnected
            print 'No active connection'

    def receive_message(curr_socket, k_sha_digest_128, inputs_list, outputs_list):
        #if can read message length, the other party is still connected
        msg_length = curr_socket.recv(AES.block_size, socket.MSG_WAITALL)
        if msg_length:
            #removes padding from msg_length
            msg_length = msg_length.strip('\0')

            #reads the rest of the transmitted information
            iv = curr_socket.recv(AES.block_size, socket.MSG_WAITALL)
            encrypted_msg_received = curr_socket.recv(int(msg_length), socket.MSG_WAITALL)

            #decrypts messaged using the hash of key k and the sent IV
            cipher = AES.new(k_sha_digest_128, AES.MODE_CBC, iv)
            msg_received = cipher.decrypt(encrypted_msg_received)

            #removes padding from msg_received
            msg_received = msg_received.strip('\0')
            sys.stdout.write(msg_received)
        #if other party disconnected
        else:
            curr_socket.close()
            inputs_list.remove(curr_socket)
            outputs_list.remove(curr_socket)
            print 'Other party disconnected. Program will now terminate.'
            sys.exit()


    def run():
        #get command line arguments and initialize socket
        connection_type, hostname = get_args()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        #if server tries to send a message
        #before the key is agreed upon (before the client connects),
        #the key will be passed as None
        k_sha_digest_128 = None

        if connection_type == 'client':
            try:
                s.connect((hostname, PORT_NUM))
                inputs_list = [s, sys.stdin]
                outputs_list = [s]

                #receive "secret" 'B' from server
                B = s.recv(1024)

                #generate a secret 'a' and send to server
                a = dh_send_generated_secret(s)

                #use "secret" 'B to obtain a hash of the agreed upon key
                k_sha_digest_128 = dh_process_received_secret(a, B)

                #starts listening for a message from the server or user input
                while True:
                    inputs_ready, outputs_ready, exceptions_ready = select.select(inputs_list, outputs_list, [])
                    for curr_socket in inputs_ready:
                        if curr_socket == sys.stdin:
                            send_message(k_sha_digest_128, outputs_ready)
                        elif curr_socket == s:
                            receive_message(curr_socket, k_sha_digest_128, inputs_list, outputs_list)
            except socket.error:
                print 'No active server at specified hostname'

        elif connection_type == 'server':
            s.bind(('', PORT_NUM))
            s.listen(1)
            inputs_list = [s, sys.stdin]
            outputs_list = []

            #start listening for hosts trying to connect, user input or messages from the client
            while True:
                inputs_ready, outputs_ready, exceptionsReady = select.select(inputs_list, outputs_list, [])
                for curr_socket in inputs_ready:
                    if curr_socket == s:
                        c, addr = s.accept()
                        inputs_list.append(c)
                        outputs_list.append(c)

                        #once a client connects, generate a secret 'a' and send to client
                        a = dh_send_generated_secret(c)

                        #receive "secret" 'B' from client
                        B = c.recv(1024)

                        #use "secret" 'B' to obtain a hash of the agreed upon key
                        k_sha_digest_128 = dh_process_received_secret(a, B)

                    elif curr_socket == sys.stdin:
                        send_message(k_sha_digest_128, outputs_ready)
                    else:
                        receive_message(curr_socket, k_sha_digest_128, inputs_list, outputs_list)

    run()

except KeyboardInterrupt:
    #user hit CTRL-C to end the program
    print '\nProgram terminated'
except EOFError:
    #user hit CTRL-D to end the program
    print 'Program terminated'
