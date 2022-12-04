package org.example;

/**
 * Hello world!
 *
 */
public class App
{
    public static void main( String[] args )
    {
        System.out.println( "Hello World!" );

        //JWTCreator jwtCreator = new JWTCreator();
        JWTCreator2 jwtCreator = new JWTCreator2();
        try {

            String data =  "{\"sub\": \"1234567890\", \"name\": \"John Doe\", \"admin\": true, \"iat\": 1516239022 }";

            String token = jwtCreator.getEncryptedString(data);
            System.out.println(token);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
