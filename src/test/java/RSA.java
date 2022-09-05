import rsa.RSAUtil;

public class RSA {
    public static void main(String[] args) throws Exception {
        System.out.println(new String(RSAUtil.Encrypt("test".getBytes(),
                "-----BEGIN PUBLIC KEY-----\n" +
                        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxSOQiTvGjApaebUdbOHw\n" +
                        "E6TKKehJqA0uR3x0IcYkh/VXgYzCT3vC7Q2cW742BEtpIdrSWmJ+/+l69Vw69ClU\n" +
                        "AwIDAQAB\n" +
                        "-----END PUBLIC KEY-----\n", 256)));

        System.out.println(new String(RSAUtil.Decrypt("l291tXP31SnjnAjRqe",
                "-----BEGIN RSA PRIVATE KEY-----\n" +
                        "MIIEogIBAAKCAQEAxSOQiTvGjApaebUdbOHwr4f88xQS5k4lVMurVYv9eXPDm+/n\n" +
                        "3nKg3a7k3SgUQuC/YX+PugKDErdF8GJC2DQJ8cKIlh3nWrCI5qs=\n" +
                        "-----END RSA PRIVATE KEY-----\n", 256)));
    }
}
