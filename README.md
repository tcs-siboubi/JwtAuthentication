# JwtAuthentication
## Topics Covered
* Generate public/private key pair using RSA and store it into file.
* Generate JWT with the genearted private key
* Claim the respose with the public key and jwt id


## Looking for something in particular?

|Spring Boot Configuration | Class or Java property files                                                                                                                                 |
|--------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|
|The Main Class | [JwtAuthenticationApplication](https://github.com/tcs-siboubi/JwtAuthentication/blob/master/src/main/java/org/example/JwtAuthenticationApplication.java) |

## Steps to test the application:

1) Once the application is installed properly, Run as Java Application.
2) Once the application successfully started means it will do the following operation:
   <ul>
   <li>generate public/private key using RSA</li>
   <li>encode and store it to file with the specified location in the top of the file, this stored public key file can be shared to your clients.</li>
   <li>generate jwt token using private key with expiry time and share the generated jwt to the clients.</li>
   <li>you can also claim the token with the public key and verify it.</li>	
   </ul>
3) You can verify the result which will be printed in the console.
   <img src="https://github.com/tcs-siboubi/JwtAuthentication/blob/master/docs/Pic1.PNG"/>
   
