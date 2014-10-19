import getopt,sys,socket,select
from Crypto.Hash import SHA
from Crypto.Hash import HMAC
from Crypto import Random
from Crypto.Cipher import AES

#Allows two computers to connect to send/receive encrypted messages to/from each other

PORT_NUM = 9999

try:
    def usage():
        #prints correct command line arguments
        print 'Usage: EncryptedIM [-s|-c hostname] [-confkey K1] [-authkey K2]'

    def get_args():
        #gets command line arguments syntax
        try:
            opts, args = getopt.getopt(sys.argv[1:], 'sc:', ['confkey=', 'authkey='])
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
            elif curr_opt == '--confkey':
                k1 = curr_arg
            elif curr_opt == '--authkey':
                k2 = curr_arg
        #if user input all arguments, return them. Else, print correct syntax and exit.
        if 'connection_type'in locals() and 'hostname' in locals() and 'k1' in locals() and 'k2' in locals():
            return connection_type, hostname, k1, k2
        else:
            usage()
            sys.exit()

    def send_message(k1_sha_digest_128, k2_sha_digest_128, outputs_ready):

        #create new cipher based on the hashed key k1 and a fresh IV
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(k1_sha_digest_128, AES.MODE_CBC, iv)

        #pads message until length is a multiple of 16
        msg_to_send = sys.stdin.readline()
        while len(msg_to_send) % AES.block_size != 0:
            msg_to_send += '\0'

        #pads a string holding the length of the message until the string length is a multiple of 16
        msg_length = str(len(msg_to_send))
        while len(msg_length) % AES.block_size != 0:
            msg_length += '\0'

        #compute new digest of a HMAC based on the hashed key k2 and the message
        k2_hmac = HMAC.new(k2_sha_digest_128, msg_to_send)
        k2_hmac_digest = k2_hmac.digest()

        #encrypts message and concatenates all pieces to send
        encrypted_msg_to_send = msg_length + iv + cipher.encrypt(msg_to_send) + k2_hmac_digest
        if len(outputs_ready) > 0:
            outputs_ready[0].send(encrypted_msg_to_send)
        else:
            #server was disconnected
            print 'No active connection'

    def receive_message(curr_socket, k1_sha_digest_128, k2_sha_digest_128, inputs_list, outputs_list):

        #if can read message length, the other party is still connected
        msg_length = curr_socket.recv(AES.block_size, socket.MSG_WAITALL)
        if msg_length:
            #removes padding from msg_length
            msg_length = msg_length.strip('\0')

            #reads the rest of the transmitted information
            iv = curr_socket.recv(AES.block_size, socket.MSG_WAITALL)
            encrypted_msg_received = curr_socket.recv(int(msg_length), socket.MSG_WAITALL)
            hmac_received = curr_socket.recv(AES.block_size, socket.MSG_WAITALL)

            #decrypts messaged using the hash of key k1 and the sent IV
            cipher = AES.new(k1_sha_digest_128, AES.MODE_CBC, iv)
            msg_received = cipher.decrypt(encrypted_msg_received)

            #computes the expected digest of a HMAC based on the hashed key k2 and the message
            k2_hmac = HMAC.new(k2_sha_digest_128, msg_received)
            k2_hmac_digest_computed = k2_hmac.digest()

            #if the received HMAC does not match the received HMAC, the message was altered in transit
            #note that this will happen when different authentication OR confidentiality keys were used
            if hmac_received != k2_hmac_digest_computed:
                print 'Received a message that was altered in transit'
                return

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
        connection_type, hostname, k1, k2 = get_args()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        #calculate first 128 bits of hash of key k1
        k1_sha = SHA.new(k1.encode())
        k1_sha_digest_128 = k1_sha.digest()[:16]

        #calculate first 128 bits of hash of key k1
        k2_sha = SHA.new(k2.encode())
        k2_sha_digest_128 = k2_sha.digest()[:16]

        if connection_type == 'client':
            try:
                s.connect((hostname, PORT_NUM))
                inputs_list = [s, sys.stdin]
                outputs_list = [s]

                #starts listening for a message from the server or user inpu
                while True:
                    inputs_ready, outputs_ready, exceptions_ready = select.select(inputs_list, outputs_list, [])
                    for curr_socket in inputs_ready:
                        if curr_socket == sys.stdin:
                            send_message(k1_sha_digest_128, k2_sha_digest_128, outputs_ready)
                        elif curr_socket == s:
                            receive_message(curr_socket, k1_sha_digest_128, k2_sha_digest_128, inputs_list, outputs_list)
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
                    elif curr_socket == sys.stdin:
                        send_message(k1_sha_digest_128, k2_sha_digest_128, outputs_ready)
                    else:
                       receive_message(curr_socket, k1_sha_digest_128, k2_sha_digest_128, inputs_list, outputs_list)

    run()

except KeyboardInterrupt:
    #user hit CTRL-C to end the program
    print '\nProgram terminated'
except EOFError:
    #user hit CTRL-D to end the program
    print 'Program terminated'
