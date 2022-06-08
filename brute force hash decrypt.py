import hashlib

class Hash_decrypt():
    
    def decrypt_MD5(self,hash_pass,path_pass):
        with open(path_pass,'rb') as file:
            for i in file:
                hash_line=hashlib.md5(i.strip())
                hash_val=hash_line.hexdigest()
                if hash_val==hash_pass:
                    return i.strip().decode()
        return False
    
    
    def decrypt_multiple_MD5(self,path_to_pass, path_to_hash):
        with open(path_to_hash,'r') as file:
            for i in file:
                dec_hash=self.decrypt_MD5(i.strip(),path_to_pass)
                if dec_hash:
                    print(dec_hash)
                else:
                    print('not found..')
                    
                    
                    
                    
    def decrypt_sha1(self,hash_pass,path_pass):
          with open(path_pass,'rb') as file:
            for i in file:
                hash_line=hashlib.sha1(i.strip())
                hash_val=hash_line.hexdigest()
                if hash_val==hash_pass:
                    return i.strip().decode()
            return False
        
        
    def decrypt_multiple_sha1(self,path_to_pass, path_to_hash):
        with open(path_to_hash,'r') as file:
            for i in file:
                dec_hash=self.decrypt_sha1(i.strip(),path_to_pass)
                if dec_hash:
                    print(dec_hash)
                else:
                    print('not found..')
                    
                    
                    
    def decrypt_sha256(self,hash_pass,path_pass):
        with open(path_pass,'rb') as file:
            for i in file:
                hash_line=hashlib.sha256(i.strip())
                hash_val=hash_line.hexdigest()
                if hash_val==hash_pass:
                    return i.strip().decode()
            return False
        
        
    def decrypt_multiple_sha256(self,path_to_pass, path_to_hash):
        with open(path_to_hash,'r') as file:
            for i in file:
                dec_hash=self.decrypt_sha256(i.strip(),path_to_pass)
                if dec_hash:
                    print(dec_hash)
                else:
                    print('not found..')
                    
    
    def decrypt_sha512(self,hash_pass,path_pass):
        with open(path_pass,'rb') as file:
            for i in file:
                hash_line=hashlib.sha512(i.strip())
                hash_val=hash_line.hexdigest()
                if hash_val==hash_pass:
                    return i.strip().decode()
            return False
        
        
    def decrypt_multiple_sha512(self,path_to_pass, path_to_hash):
        with open(path_to_hash,'r') as file:
            for i in file:
                dec_hash=self.decrypt_sha512(i.strip(),path_to_pass)
                if dec_hash:
                    print(dec_hash)
                else:
                    print('not found..')
             

def main():
    p=int(input('to decrypt single hash enter 1\nto decrypt multiple hashes enter 2: '))
    algo=input('please enter the algorithm type of the hash to decrypt: ')
    if p==1:
        path=str(input('\nplease enter path of password list, your hash to decrypt.<path>,<hash> (ex: C:\\Users\\name\\pass.txt, 36b622ca1f9..)\n'))
        path=path.split(",")
        path_pass=path[0].strip()
        hash_to_decrypt=path[-1].strip()
        print("Loading results...\n")
        if algo=='md5'or algo=='MD5':
            print('hash =',Hash_decrypt().decrypt_MD5(hash_to_decrypt,path_pass))
        elif algo=='sha1':
            print('hash =',Hash_decrypt().decrypt_sha1(hash_to_decrypt,path_pass))
        elif algo=='sha256':
            print('hash =',Hash_decrypt().decrypt_sha256(hash_to_decrypt,path_pass))
        elif algo=='sha512':
            print('hash =',Hash_decrypt().decrypt_sha512(hash_to_decrypt,path_pass))

    else:
        path=str(input('\nplease enter path of passwords list and path of hashes to decrypt.<path to passwords>,<path to hashes>\n(ex: C:\\Users\\name\\pass.txt, C:\\Users\\name\\hashes.txt)\n'))
        path=path.split(",")
        path_pass=path[0].strip()
        path_hash=path[-1].strip()
        print("\nLoading results...\n"+('-'*18))
        if algo=='md5'or algo=='MD5':
            Hash_decrypt().decrypt_multiple_MD5(path_pass,path_hash)
        elif algo=='sha1':
            Hash_decrypt().decrypt_multiple_sha1(path_pass,path_hash)
        elif algo=='sha256':
            Hash_decrypt().decrypt_multiple_sha256(path_pass,path_hash)
        elif algo=='sha512':
            Hash_decrypt().decrypt_multiple_sha512(path_pass,path_hash)




if __name__=="__main__":
    main()

