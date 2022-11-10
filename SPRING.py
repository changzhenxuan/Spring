import numpy as np

def text2matrix(text,text_len):
    try:
        matrix = []
        byte_num = text_len // 8     
        for i in range(byte_num):
            byte = (text >> (8 * (byte_num - 1 - i))) & 0xFF
            if i % 4 == 0:
                matrix.append([byte])
            else:
                matrix[i // 4].append(byte)
        return matrix
    except:
        print('the length of text is wrong.')

def matrix2text(matrix,text_len):
    try:
        text = 0
        for i in range(len(matrix)):
            for j in range(4):
                text |= (matrix[i][j] << (text_len - 8 - 8 * (4 * i + j)))
        return text
    except:
        print('matrix wrong.')

class Spring():
    def __init__(self, Key, text_len=128, key_len=128, mode='ECB', IV=0):
        # 初始化S盒
        # self.make_sbox_table()
        self.make_sbox_table_2()
        # 加密模式
        if mode == 'CBC':
            self.cipher_mode = 'CBC'
            self.IV = IV
        else:
            self.cipher_mode = 'ECB'
        # 密钥长度和分组长度
        if key_len == 128 and text_len == 128:
            self.key_len = 128      # 密钥长度128bit
            self.text_len = 128     # 分组长度128bit
            self.round_num = 10
            self.key_lfsr_step = 16
            self.bunch_num_in_nfsr = 2  # 每个密钥寄存器中包含多少个字节
            self.bit_num_one_bunch = 16 # 每个密钥寄存器长度
            self.step = 1   # 跳几个寄存器取已一次值
            self.startpoint = 0
            self.flag = 0xffffffffffffffffffffffffffffffff
            self.round_keys = self.key_expansion(Key, 0)  #加密轮密钥
            self.round_keys_inv = self.key_expansion(Key, 1) #解密轮密钥

        elif key_len == 256 and text_len == 128:
            self.key_len = 256
            self.text_len = 128
            self.round_num = 14
            self.key_lfsr_step = 32
            self.bunch_num_in_nfsr = 4
            self.bit_num_one_bunch = 32
            self.step = 2
            self.startpoint = 1
            self.flag = 0xffffffffffffffffffffffffffffffff
            self.round_keys = self.key_expansion(Key, 0)  #加密轮密钥
            self.round_keys_inv = self.key_expansion(Key, 1) #解密轮密钥

        elif key_len == 256 and text_len == 256:
            self.key_len = 256
            self.text_len = 256
            self.round_num = 18
            self.key_lfsr_step = 32
            self.bunch_num_in_nfsr = 4
            self.bit_num_one_bunch = 32
            self.step = 1
            self.startpoint = 0
            self.flag = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
            self.round_keys = self.key_expansion(Key, 0)  #加密轮密钥
            self.round_keys_inv = self.key_expansion(Key, 1) #解密轮密钥

    def encrypt(self, plain_text):
        if self.cipher_mode == 'ECB':
            return self.encrypt_ecb(plain_text)
        elif self.cipher_mode == 'CBC':
            return self.encrypt_cbc(plain_text)
        
    def decrypt(self, cipher_text):
        if self.cipher_mode == 'ECB':
            return self.decrypt_ecb(cipher_text)
        elif self.cipher_mode == 'CBC':
            return self.decrypt_cbc(cipher_text)

    def encrypt_ecb(self, plain_text):
        self.in_len = len(plain_text)
        self.block_num = self.in_len // (self.text_len // 4)
        if self.in_len % (self.text_len // 4) != 0:
            self.block_num += 1
            plain_text = self.pad(plain_text)
        cipher_text = ''
        for i in range(self.block_num):
            plain_text_block = eval('0x'+plain_text[(self.text_len//4)*i : (self.text_len//4)*(i+1)])
            temp = plain_text[(self.text_len//4)*i : (self.text_len//4)*(i+1)]
            temp_enc = hex(self.encrypt_block(plain_text_block))[2:]
            temp_enc_pad2 = self.pad2(temp_enc)
            cipher_text = cipher_text +  self.pad2(hex(self.encrypt_block(plain_text_block))[2:])
        return cipher_text
    
    def encrypt_cbc(self, plain_text):
        self.in_len = len(plain_text)
        self.block_num = self.in_len // (self.text_len // 4)
        if self.in_len % (self.text_len // 4) != 0:
            self.block_num += 1
            plain_text = self.pad(plain_text)
        plain_text_block = eval('0x'+plain_text[:self.text_len//4])         # 第一组明文 字符串-->数字
        cipher_text_block = self.encrypt_block(plain_text_block ^ self.IV)  # 数字
        cipher_text = self.pad2(hex(cipher_text_block)[2:])                           # 字符串
        for i in range(1, self.block_num):
            plain_text_block = eval('0x' + plain_text[(self.text_len//4)*i : (self.text_len//4)*(i+1)])
            cipher_text_block_pre = eval('0x'+cipher_text[-(self.text_len//4):])
            cipher_text = cipher_text +  self.pad2(hex(self.encrypt_block(plain_text_block ^ cipher_text_block_pre))[2:])
        return cipher_text
    
    def decrypt_ecb(self, cipher_text):
        self.in_len = len(cipher_text)
        self.block_num = self.in_len // (self.text_len // 4)
        if self.in_len % (self.text_len // 4) != 0:
            print('the length of cipher_text is invalide.')
            return -1
        plain_text = ''
        for i in range(self.block_num):
            cipher_text_block = eval('0x'+cipher_text[(self.text_len//4)*i : (self.text_len//4)*(i+1)])
            plain_text = plain_text + self.pad2(hex(self.decrypt_block(cipher_text_block))[2:])
        return plain_text
    
    def decrypt_cbc(self, cipher_text):
        self.in_len = len(cipher_text)
        self.block_num = self.in_len // (self.text_len // 4)
        if self.in_len % (self.text_len // 4) != 0:
            self.block_num += 1
            cipher_text = self.pad(cipher_text)
        cipher_text_block = eval('0x'+cipher_text[ : self.text_len//4])
        plain_text_block = self.decrypt_block(cipher_text_block) ^ self.IV
        plain_text = self.pad2(hex(plain_text_block)[2:])
        for i in range(1, self.block_num):
            cipher_text_block_pre = cipher_text_block
            cipher_text_block = eval('0x'+cipher_text[(self.text_len//4)*i : (self.text_len//4)*(i+1)])
            plain_text = plain_text + self.pad2(hex(self.decrypt_block(cipher_text_block) ^ cipher_text_block_pre)[2:])
        return plain_text
    
    def encrypt_block(self, plain_text_block):
        self.plain_state = text2matrix(plain_text_block, self.text_len)
        # round*(self.round_num-1)
        for i in range(self.round_num-1):
            self.add_round_key(self.plain_state, self.round_keys[i])
            self.sub_row(self.plain_state)
            self.p_layer(self.plain_state)
        # final_round
        self.add_round_key(self.plain_state, self.round_keys[self.round_num-1])
        self.sub_row(self.plain_state)
        self.add_round_key(self.plain_state, self.round_keys[self.round_num])
        self.l_layer(self.plain_state)
        return matrix2text(self.plain_state, self.text_len)

    def decrypt_block(self, cipher_text_block):
        self.cipher_state = text2matrix(cipher_text_block, self.text_len)
        
        self.add_round_key(self.cipher_state, self.round_keys_inv[0])
        for i in range(1,self.round_num):
            self.sub_row_inv(self.cipher_state)
            self.add_round_key(self.cipher_state, self.round_keys_inv[i])
            self.p_layer_inv(self.cipher_state)
        self.sub_row_inv(self.cipher_state)
        self.add_round_key(self.cipher_state, self.round_keys_inv[self.round_num])
        self.l_layer(self.cipher_state)
        return matrix2text(self.cipher_state, self.text_len)

    def pad(self, text):
        padding_len = self.block_num * (self.text_len // 4) - self.in_len
        return text + '0'*(padding_len)
    
    def pad2(self, text):
        padding_len = (self.text_len // 4) - len(text)
        return '0'*(padding_len) + text
    
    def add_round_key(self, state, round_key):
        for i in range(len(state)):
            for j in range(4):
                state[i][j] ^= round_key[4*i+j]
    
    def sub_row(self, state):
        f = [0]*3
        for i in range(len(state)):
            for j in range(4):
                f[0],f[1],f[2] = state[i][0],state[i][1],state[i][2]
                state[i][0] = self.Sbox0[state[i][2]^state[i][3]][state[i][0]]
                state[i][1] = self.Sbox1[(f[0]^state[i][3])][state[i][1]]
                state[i][2] = self.Sbox2[(f[0]^f[1])][state[i][2]]
                state[i][3] = self.Sbox3[(f[2]^f[1])][state[i][3]]
                
    def sub_row_inv(self, state):
        for i in range(len(state)):
            self.inv_s_box_32bit(state[i])
        
    def p_layer(self, state):
        sp = [l.copy() for l in state]
        if self.text_len == 128:
            for i in range(4):
                for j in range(4):
                    state[i][j] = sp[j][i]
        elif self.text_len == 256:
            for i in range(8):
                for j in range(4):
                    state[i][j] = sp[j+((i&0x01)<<2)][i>>1]
    
    def p_layer_inv(self, state):
        sp = [s.copy() for s in state]
        if self.text_len == 128:
            for i in range(4):
                for j in range(4):
                    state[i][j] = sp[j][i]
        elif self.text_len == 256:
            for i in range(8):
                for j in range(4):
                    state[i][j] = sp[(j<<1)+(i>>2)][i&0x3]
        
    def l_layer(self, state):
        if self.text_len == 128:
            sbox_num = 3
        elif self.text_len == 256:
            sbox_num = 7
        sl = [s.copy() for s in state]
        for i in range(sbox_num+1):
            for j in range(4):
                state[i][j]=((sl[sbox_num-i][3-j]&(0x01))<<7)^\
                ((sl[sbox_num-i][3-j]&(0x02))<<5)^\
                ((sl[sbox_num-i][3-j]&(0x04))<<3)^\
                ((sl[sbox_num-i][3-j]&(0x08))<<1)^\
                ((sl[sbox_num-i][3-j]&(0x10))>>1)^\
                ((sl[sbox_num-i][3-j]&(0x20))>>3)^\
                ((sl[sbox_num-i][3-j]&(0x40))>>5)^\
                ((sl[sbox_num-i][3-j]&(0x80))>>7)
    
    def inv_s_box_32bit(self, nfsr):
        f, sum = [0]*4, 0
        for step in range(32):
            f[0] = nfsr[0]^((nfsr[0]>>3)&(nfsr[0]>>4))^(nfsr[0]>>6)
            f[1] = nfsr[1]^((nfsr[1]>>3)&(nfsr[1]>>4))^(nfsr[1]>>5)
            f[2] = nfsr[2]^((nfsr[2]>>4)&(nfsr[2]>>5))^(nfsr[2]>>3)
            f[3] = nfsr[3]^((nfsr[3]>>4)&(nfsr[3]>>5))^(nfsr[3]>>2)
            sum=f[0]^f[1]^f[2]^f[3]
            for i in range(4):
                nfsr[i]=(nfsr[i]>>1)^(((sum^f[(i+1)&0x03])&0x01)<<7)
    
    def count_sbox(self,nfsr):
        f = [0] * 4
        for step in range(4):
            f[0]= nfsr[0]^((nfsr[0]>>3)&(nfsr[0]>>4))^(nfsr[0]>>6)^nfsr[3]^nfsr[2]
            f[1]= nfsr[1]^((nfsr[1]>>3)&(nfsr[1]>>4))^(nfsr[1]>>5)^nfsr[0]^nfsr[3]
            f[2]= nfsr[2]^((nfsr[2]>>4)&(nfsr[2]>>5))^(nfsr[2]>>3)^nfsr[1]^nfsr[0]
            f[3]= nfsr[3]^((nfsr[3]>>4)&(nfsr[3]>>5))^(nfsr[3]>>2)^nfsr[2]^nfsr[1]
            for i in range(4):
                nfsr[i] = (nfsr[i]>>2)^((f[i]&0x03)<<6)
        
    def make_sbox_table(self):
        self.Sbox0,self.Sbox1 = [[0]*256 for i in range(256)], [[0]*256 for i in range(256)]
        self.Sbox2,self.Sbox3 = [[0]*256 for i in range(256)], [[0]*256 for i in range(256)]
        N = [127]*4
        st, st2 = 0, 0
        for st2 in range(256):
            for st in range(256):
                N[3],N[2],N[0] = st2,0,st
                self.count_sbox(N)
                self.Sbox0[st2][st] = N[0]
                
                N[3],N[0],N[1] = st2,0,st
                self.count_sbox(N)
                self.Sbox1[st2][st] = N[1]
                
                N[0],N[1],N[2] = st2,0,st
                self.count_sbox(N)
                self.Sbox2[st2][st] = N[2]
                
                N[1],N[2],N[3] = st2,0,st
                self.count_sbox(N)
                self.Sbox3[st2][st] = N[3]
                
    def make_sbox_table_2(self):
        with open('Sbox0.txt', 'r') as f:
            self.Sbox0 = [eval(s) for s in f.read().split('\n')]
        with open('Sbox1.txt', 'r') as f:
            self.Sbox1 = [eval(s) for s in f.read().split('\n')]
        with open('Sbox2.txt', 'r') as f:
            self.Sbox2 = [eval(s) for s in f.read().split('\n')]
        with open('Sbox3.txt', 'r') as f:
            self.Sbox3 = [eval(s) for s in f.read().split('\n')]
        
    def key_expansion(self, seed_key, direction):
        CS1 = [0xc0,0x24,0x3b,0x41,0x6d,0x4d,0xc3,0xb7,0xd7,0x45,0xd8,0x78,0xce,0x68,0x89,0x52,0xb9,0x9b] # 加密轮常值
        CS2 = [0x3,0x24,0xdc,0x82,0xb6,0xb2,0xc3,0xed,0xeb,0xa2,0x1b,0x1e,0x73,0x16,0x91,0x4a,0x9d,0xd9]	# 解密轮常值
        if self.key_len == 128 or self.key_len == 256:
            self.KS, f, fc = [0]*8, [0]*8, 0
            for i in range(8):
                for j in range(self.bunch_num_in_nfsr):
                    self.KS[i]=((seed_key >> 8*(self.key_len//8-1-(self.bunch_num_in_nfsr*i+j))) & 0xff) + (self.KS[i]<<8)		# 装载寄存器状态
            
            if direction == 0:
                round_keys = []
                for i in range(self.round_num + 1):
                    round_keys.append([])
                    count = 0
                    while count<8:
                        for k in range(self.bunch_num_in_nfsr):
                            round_keys[i].append((self.KS[count] >> 8*(self.bunch_num_in_nfsr-1-k)) & 0xff) # 取寄存器状态作第一个子密钥
                        count = count + self.step
                    if i != self.round_num:
                        self.key_nfsr_update(CS1[i])
                return round_keys
            else:
                for i in range(self.round_num):
                    self.key_nfsr_update(CS1[i])  # 更新至加密过程最后一轮的寄存器状态
                self.up_side_down_nfsrs()
                round_keys_inv = []
                for i in range(self.round_num + 1):
                    round_keys_inv.append([])
                    count = self.startpoint
                    while count<8:
                        for k in range(self.bunch_num_in_nfsr):
                            round_keys_inv[i].append((self.KS[count] >> 8*(self.bunch_num_in_nfsr-1-k)) & 0xff) # 取寄存器状态作第一个子密钥
                        count = count + self.step
                    if i != self.round_num:
                        self.inv_key_nfsr_update(CS2[self.round_num-1-i])
                return round_keys_inv
        elif self.key_len == 256:
            pass
    
    def up_side_down_nfsrs(self):
        length, number, temp = self.bit_num_one_bunch, 8, 0
        for i in range(number):
            temp = self.KS[i]
            self.KS[i] = 0
            for j in range(length // 2):
                self.KS[i] = self.KS[i] ^ ((temp&(0x01<<j))<<(length-1-2*j))^((temp&(0x01<<(length-j-1)))>>(length-1-2*j))
        for i in range(number // 2):
            self.KS[i], self.KS[number-1-i] = self.KS[number-1-i], self.KS[i]

    def key_nfsr_update(self, CS):
        f = [0]*8
        if self.key_len == 128:
            flag = 0xffff
            num1, num2, num3, num4 = 3, 8, 7, 10
        elif self.key_len == 256:
            flag = 0xffffffff
            num1, num2, num3, num4 = 5, 15, 16, 24
        self.KS[0] = self.KS[0]^(CS<<(self.bit_num_one_bunch-8))
        for k in range(self.key_lfsr_step):
            for j in range(4):
                f[j]=( (self.KS[j]>>1)^(self.KS[j]>>(num1+j))^( (self.KS[j]>>(num2+1))&(self.KS[j]>>num2) )^(self.KS[(j+7)&0x7]) )&0x01	# 前4个寄存器更新函数
                f[j+4]=( (self.KS[j+4]>>(self.bit_num_one_bunch-1))^(self.KS[j+4]>>(num4+j))^( (self.KS[j+4]>>num3)&(self.KS[j+4]>>(num3+1)))^( self.KS[(j+3)] ) )&0x01	# 后4个寄存器更新函数
            for j in range(8):
                self.KS[j] = (((self.KS[j]&flag)>>1)^((f[j]&0x01)<<(self.bit_num_one_bunch-1)))	# 寄存器移位
                
    def inv_key_nfsr_update(self, CS):
        f = [0]*8
        if self.key_len == 128:
            flag = 0xffff
            num1, num2, num3, num4 = 3, 8, 7, 10
        elif self.key_len == 256:
            flag = 0xffffffff
            num1, num2, num3, num4 = 5, 15, 16, 24
        for k in range(self.bit_num_one_bunch):
            for j in range(4):
                f[j]=( (self.KS[j]>>1)^(self.KS[j]>>(num1+j))^( (self.KS[j]>>(num2+1))&(self.KS[j]>>num2) )^self.KS[j])&0x01		# 前4个寄存器更新函数
                f[j+4]=( (self.KS[j+4]>>(self.bit_num_one_bunch-1))^(self.KS[j+4]>>(num4+j))^( (self.KS[j+4]>>num3)&(self.KS[j+4]>>(num3+1)))^self.KS[j+4])&0x01 # 后4个寄存器更新函数
            for j in range(8):
                self.KS[j]=((self.KS[j]>>1)^((f[(j+7)&0x07])<<(self.bit_num_one_bunch-1)))&flag
        self.KS[7] ^= CS
        
        

if __name__ == '__main__':
    s = Spring(0x80f147f7bd1c5c3ab33a3d1ac43408d5, 128,128,'CBC')
    plain_text = '855c91781f45ef52f6d73ba888a294aa977366a68a25ec7c11baf45208abe3889e7bf8eeb692d5358d493ba49d42150cc2fab8fe9ca1693b34291f6ce29d8b146eb456c275a6aa8b0e3ef3b7ae30e7bb49aec468ba36d86165ae47d21bb2095f3e2d325b2526763bc1ddec4a8117129e74b6124aae8c43d5ec71f3eb7b936453550e14218ebd412dee4fadc3e09d9f9c8a3a2a0d3e4cb17f119bab1fc9e8a4d7fd80847c77111449ddbbbe8c916a959fd564951a331e2b471c54f8d6cf58d2d27cab0bd4a9caf677d64aa80b5c27fc8e9b5adad854a9b81554c36078538cf42e1bb63091ed91f09f2024f2aa0b7cdc50254481ae6b9660d102116d6d1e2c15d2'
    cipher_text = s.encrypt(plain_text)
    # cipher_text = '8e16e05d7d9975ca4980cbdf9f1041d8d0323b9c1191f1dd47388118b106cb85b5caf84cbea4e17bbfe9828acc8240047d2482732f610b91a19034842d0cd907c0e182c50c8e65d6c03ef911ab56926365288120bd9e6460c8befd02a1e845fb77cd3b89d03a027d42e51a5c42d0129d9e732baad4828e25b3c71c87520609761d4f7dfbfa4124237b9a18a8a16e200832e45b39ce75ff5065af19f3c297921b9b38b21f97dc5b16ced155b63f677dfcd478da1d3e69fcd2d66b8270fca815db1f493c047045960f62baa61228b2f84b45746a5b67e60151f54cf444762748b719838b8be1318b2c1a96d5931e23e52e150b32e12e9b8f428fdcf7ddd4d4e1e'
    print(s.decrypt(cipher_text))