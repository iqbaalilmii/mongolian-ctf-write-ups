# Write-up: Haruul Zangi Memory Forensics Challenge

Challenge Information
Target: Linux Memory Dump (memhunt.mem)

Category: Memory Forensics & Cryptography


Pertama, aku coba pake plugin windows.info, tapi gabisa, dan aku coba pake plugin banners.Banners buat nentuin kernel linux yang spesifik karna volatility butuh symbol table buat baca struktur data di memory.
```
vol3 -f memhunt.mem banners.Banners
```
<img width="1920" height="1128" alt="image" src="https://github.com/user-attachments/assets/e72c55d3-c8f2-4033-8d8b-5c8a465f35bc" />
ternyata, ini pake Linux version 4.15.0-213-generic, aku langsung aja cari file .ddeb yang sesuai di repositori Ubuntu (linux-image-unsigned-4.15.0-213-generic-dbgsym). Menggunakan tool dwarf2json untuk mengubah file vmlinux dari paket debug tersebut menjadi file .json

Setelah simbol terpasang, aku langsung cek bash history pake `linux.bash.Bash`.
<img width="1920" height="1128" alt="image" src="https://github.com/user-attachments/assets/5fa24b2b-7524-4d91-ac64-d56055719e67" />
terlihat user menginstall LiMe (Linux Memory Extractor) untuk ngambil dump memori, dia juga coba menghapus jejak dengan perintah rm ~/.bash_history dan cat /dev/null > ~/.bash_history.

setelah itu, aku check proses list yang lagi jalan pake plugin `linux.pslist`
<img width="1920" height="1128" alt="image" src="https://github.com/user-attachments/assets/f4a10af7-4b65-4ae4-aa73-4619528fd13e" />

dan nemuin prosess java yang mencurigakan, kenapa? karna UIDnya 0 yang berarti yang ngejalanin root, disini karna proses java itu mencurigakan banget, aku langsung aja dump pake plugin `linux.pagecache.RecoverFs`
<img width="1405" height="818" alt="image" src="https://github.com/user-attachments/assets/ccec4627-e424-4cbe-b98d-65797aa05f0d" />

file tar.gznya di decompress dengan `tar -xzvf recovered_fs.tar.gz`, dan aku langsung aja find file java mencurigakan tadi, dan menemukan path `./extracted_files/262cd342-5473-4dde-8b29-fff35b4a0bb8/home/zangi/zan/needed.java`

langsung aja di cat dan nemuin script java ini
<img width="1920" height="1128" alt="image" src="https://github.com/user-attachments/assets/143406a1-6da8-44bb-8479-2687b94afb7c" />
langsung aja di cat dan nemuin script java ini
```
import javax.crypto.Cipher; import java.security.*; import java.security.spec.PKCS8EncodedKeySpec; import java.security.spec.X509EncodedKeySpec; import java.util.Base64;

class RSA {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    private static final String PRIVATE_KEY_STRING =
"MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJhBgzcXBm5A0srvFFu4FsBy+LLW+X0sH/9RvP40VIGOCusY0/CqA65YXWqyQE5jQCegBmnAeVYSvK+3PU4Y1fmr1uiquE6sZB5sl96T0ka+PKzPf4oKoAi6nwLUSenj5xTFjLsFGiuMXrCpMCPImf9JBVk89TJV43Xs3DSNKoj1AgMBAAECgYBsDysCgVv2ChnRH4eSZP/4zGCIBR0C4rs+6RM6U4eaf2ZuXqulBfUg2uRKIoKTX8ubk+6ZRZqYJSo3h9SBxgyuUrTehhOqmkMDo/oa9v7aUqAKw/uoaZKHlj+3p4L3EK0ZBpz8jjs/PXJc77Lk9ZKOUY+T0AW2Fz4syMaQOiETzQJBANF5q1lntAXN2TUWkzgir+H66HyyOpMu4meaSiktU8HWmKHa0tSB/v7LTfctnMjAbrcXywmb4ddixOgJLlAjEncCQQC6Enf3gfhEEgZTEz7WG9ev/M6hym4C+FhYKbDwk+PVLMVR7sBAtfPkiHVTVAqC082E1buZMzSKWHKAQzFL7o7zAkBye0VLOmLnnSWtXuYcktB+92qh46IhmEkCCA+py2zwDgEiy/3XSCh9Rc0ZXqNGD+0yQV2kpb3awc8NZR8bit9nAkBo4TgVnoCdfbtq4BIvBQqR++FMeJmBuxGwv+8n63QkGFQwVm6vCuAqFHBtQ5WZIGFbWk2fkKkwwaHogfcrYY/ZAkEAm5ibtJx/jZdPEF9VknswFTDJl9xjIfbwtUb6GDMc0KH7v+QTBW4GsHwt/gL+kGvLOLcEdLL5rau3IC7EQT0ZYg==";
    private static final String PUBLIC_KEY_STRING =
"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCYQYM3FwZuQNLK7xRbuBbAcviy1vl9LB//Ubz+NFSBjgrrGNPwqgOuWF1qskBOY0AnoAZpwHlWEryvtz1OGNX5q9boqrhOrGQebJfek9JGvjysz3+KCqAIup8C1Enp4+cUxYy7BRorjF6wqTAjyJn/SQVZPPUyVeN17Nw0jSqI9QIDAQAB";


    public void init(){
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(1024);
            KeyPair pair = generator.generateKeyPair();
            privateKey = pair.getPrivate();
            publicKey = pair.getPublic();
        } catch (Exception ignored) {
        }
    }

    public void initFromStrings(){
        try{
            X509EncodedKeySpec keySpecPublic = new X509EncodedKeySpec(decode(PUBLIC_KEY_STRING));
            PKCS8EncodedKeySpec keySpecPrivate = new PKCS8EncodedKeySpec(decode(PRIVATE_KEY_STRING));

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            publicKey = keyFactory.generatePublic(keySpecPublic);
            privateKey = keyFactory.generatePrivate(keySpecPrivate);
        }catch (Exception ignored){}
    }


    public void printKeys(){
        //System.err.println("Public key\n"+ encode(publicKey.getEncoded()));
        //System.err.println("Private key\n"+ encode(privateKey.getEncoded()));
    }

    private static String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }
    private static byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }

    public String decrypt(String encryptedMessage) throws Exception {
        byte[] encryptedBytes = decode(encryptedMessage);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedMessage = cipher.doFinal(encryptedBytes);
        return new String(decryptedMessage, "UTF8");
    }

    public static void main(String[] args) {

        RSA rsa = new RSA();
        rsa.initFromStrings();
        try{
                        int i = 0;
                        while (i < 50000000)
                        {
                                System.out.println(i);
                                 i++;
                        }
            String encryptedMessage =
"UnKTJXJTMaQB1Lsuc+0Np2xE5tybReUrssXF+SEeuAzZaz4t5Ka/SI9qBk45ru8evydr2AV8lWpsgGjF7WixJaBQVvv5rw7wZGhwi/CJ39qXyBpyR7/qXV2o2Nxw9lN3QZzHwWpKSl9InatYlkzVgwIoi0qiTAJ8P6XcK4j8Kdw=";
            String decryptedMessage = rsa.decrypt(encryptedMessage);


         }catch (Exception ingored){}
    }
}
```
langsung aja wok, decrypt pake tools online CyberChef

<img width="1919" height="956" alt="image" src="https://github.com/user-attachments/assets/f514c26a-bcd8-4bff-ab0c-65eb5d178136" />

```
HZ2023{MNSEC_HARUULZANGI_Q1RGLSJOHqlTRr76RnWTl4lJW1juYR1b}
```
