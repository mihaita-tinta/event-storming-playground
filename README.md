# event-storming-playground

Agenda:
- Microservices introduction
- Big Picture Event Storming - Events Organiser Startup
- Coding

## Microservices introduction

- What kind of applications do we write?
- Typical Java enterprise architecture.
- Symptoms
  - Delivery is slow (code changes, e2e)
  - Codebase difficult to maintain (slow tests, coordinated changes)
  - Application difficult to scale (hardware constraints)
  - Wasted developer time (meetings, bugs, huge classes, shared libraries)
- Monolithic hell
- Example of architecture of a monolith
- Advantages (easy to develop, radical changes, test, deploy, scale)

#### Why using a microservice architecture
- Scale cube
- Example of microservice decomposition
- Principles used by microservices (API, own DB, smart endpoints/dumb pipes, data model per service)
- Benefits of using a microservice architecture (testing, deploy, teams, time to market, reliability, employee satisfaction, adopt technologies)
- Challenges (distributed monolith, IPC challenges, transactions, queries, automation, rollout plan, when)


## Big Picture Event Storming - Events Organiser Startup

We are part of a new startup and we need to implement an Events Organiser System allowing participants to join events created by our users.
We run a Big Picture Event Storming workshop to discover the business domain.

## Coding

Based on our previous discoveries, we are required to implement a Prototype to validate our model.

We start from a simple skeleton using the lastest Spring Boot version. Click [here](https://start.spring.io/starter.zip?type=maven-project&language=java&bootVersion=3.0.1&baseDir=api&groupId=playground&artifactId=api&name=api&description=Demo%20project%20for%20Spring%20Boot&packageName=playground.api&packaging=jar&javaVersion=17&dependencies=web,data-jpa,mysql,security,validation,restdocs,kafka,actuator) to download the zip.

The following dependencies are used:
![dependencies](docs/dependencies.png)


### Repositories
We usually need to represent users in our applications.

Entity:

```java
@Entity
@Table(uniqueConstraints = @UniqueConstraint(columnNames = "email"))
public class MyUser {

    @Id
    @GeneratedValue
    private Long id;

    @NonNull
    private String username;

    // other fields we identified if any ...
}
```
Repository:

```java
public interface MyUserRepository extends JpaRepository<MyUser, Long> {
    
}
```
Test:
```java
@DataJpaTest
class MyUserRepositoryTest {
     private static final Logger log = LoggerFactory.getLogger(MyUserRepositoryTest.class);

    @Autowired
    MyUserRepository repository;

    @Test
    public void test() {
        repository.findAll().forEach(user -> log.info("Found user - id: {}", user.getId()));
    }
}
```
### DTOs
I can think of two reasons of using DTOs in our application.

- expose less information from our internal model. Once you provide some fields to your clients, it will be hard to remove them.
- prevent mass injection attacks

```xml

<properties>
    <java.version>17</java.version>
    <org.mapstruct.version>1.4.2.Final</org.mapstruct.version>
</properties>

<dependencies>
    <dependency>
        <groupId>org.mapstruct</groupId>
        <artifactId>mapstruct</artifactId>
        <version>${org.mapstruct.version}</version>
    </dependency>
    <!-- ... -->
</dependencies>

<plugins>
    <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-compiler-plugin</artifactId>
        <version>3.5.1</version> <!-- or newer version -->
        <configuration>
            <source>${java.version}</source> <!-- depending on your project -->
            <target>${java.version}</target> <!-- depending on your project -->
            <annotationProcessorPaths>
                <path>
                    <groupId>org.mapstruct</groupId>
                    <artifactId>mapstruct-processor</artifactId>
                    <version>${org.mapstruct.version}</version>
                </path>
                <!-- other annotation processors -->
            </annotationProcessorPaths>
            <compilerArgs>
                <arg>-parameters</arg>
            </compilerArgs>
        </configuration>
    </plugin>
</plugins>
```
Mapper:
```java
@Mapper
public interface UserDtoMapper {
    UserDtoMapper INSTANCE = Mappers.getMapper(UserDtoMapper.class);
    UserDto convert(MyUser user);
}

```

### Authentication

Activate Spring Security

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfiguration {

    @Bean
    public UserDetailsService userDetailsService(MyUserRepository userRepository) {
        return username -> userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
       
        http
                .authorizeHttpRequests()
                .requestMatchers("/actuator/health")
                .permitAll()
                .and()
                .authorizeHttpRequests()
                .requestMatchers("/actuator/**")
                .hasRole("ADMIN")
                .and()
                .authorizeHttpRequests()
                .anyRequest().authenticated()
                .and()
                .csrf().disable()
                .httpBasic();
        return http.build();
    }
}
```

Our API has to identify the current user based on a token.

```xml
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-api</artifactId>
            <version>0.11.5</version>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-jackson</artifactId>
            <version>0.11.5</version>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-impl</artifactId>
            <version>0.11.5</version>
        </dependency>
```
We can play around with JWTs

```java
@Component
public class JwtTokenService {
    private Clock clock = DefaultClock.INSTANCE;

    @Value("${jwt.signing.key.secret}")
    private String secret;

    @Value("${jwt.token.expiration.in.seconds}")
    private Long expiration;

    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public Date getIssuedAtDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getIssuedAt);
    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(clock.now());
    }

    private Boolean ignoreTokenExpiration(String token) {
        // here you specify tokens, for that the expiration is ignored
        return false;
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return doGenerateToken(claims, userDetails.getUsername());
    }

    private String doGenerateToken(Map<String, Object> claims, String subject) {
        final Date createdDate = clock.now();
        final Date expirationDate = calculateExpirationDate(createdDate);

        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(createdDate)
                .setExpiration(expirationDate).signWith(SignatureAlgorithm.HS512, secret).compact();
    }

    public Boolean canTokenBeRefreshed(String token) {
        return (!isTokenExpired(token) || ignoreTokenExpiration(token));
    }

    public String refreshToken(String token) {
        final Date createdDate = clock.now();
        final Date expirationDate = calculateExpirationDate(createdDate);

        final Claims claims = getAllClaimsFromToken(token);
        claims.setIssuedAt(createdDate);
        claims.setExpiration(expirationDate);

        return Jwts.builder().setClaims(claims).signWith(SignatureAlgorithm.HS512, secret).compact();
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        MyUser user = (MyUser) userDetails;
        final String username = getUsernameFromToken(token);
        return (username.equals(user.getUsername()) && !isTokenExpired(token));
    }

    private Date calculateExpirationDate(Date createdDate) {
        return new Date(createdDate.getTime() + expiration * 1000);
    }
}
```

Create a JWT filter using `OncePerRequestFilter`

```java
// somewhere in the filter ...
        logger.debug("JWT_TOKEN_USERNAME_VALUE '{}'", username);
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            UserDetails userDetails = this.userRepository.findByEmail(username)
                    .orElseThrow();

            if (jwtTokenService.validateToken(jwtToken, userDetails)) {
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
        }
```

Don't forget to add the filter in the Spring Security Config.
```java
.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
```

Update the properties. **Note that secret should be retrived from a keyvault or something similar.**
```text
jwt.signing.key.secret=mySecretmySecretmySecretmySecretmySecretmySecretmySecretmySecretmySecretmySecretmySecretmySecretmySecretmySecretmySecretmySecretmySecretmySecretmySecretmySecretmySecretmySecretmySecretmySecretmySecretmySecretmySecretmySecretmySecret
jwt.token.expiration.in.seconds=604800
```

Rest Controller
```java
@RestController
@RequestMapping("/api")
public class UserController {
    
    @GetMapping("/users/whoami")
    public UserDto getAuthentication(@AuthenticationPrincipal MyUser principal) {
        return UserDtoMapper.INSTANCE.convert(principal);
    }
}
```
Test
```java
@WebMvcTest
@AutoConfigureMockMvc
@Import(UsersMock.class)
class MyUserResourceTest {

    @Autowired
    MockMvc mockMvc;

    @Test
    @WithUserDetails(userDetailsServiceBeanName = "myUserDetailsService")
    public void test() throws Exception {

        mockMvc.perform(get("/api/users/whoami"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("user"));
    }
}
```

### Publish events

To connect to kafka we need a kafka client. Therefore, we need to add a few dependencies.
```xml
<dependencies>
        <dependency>
            <groupId>org.springframework.kafka</groupId>
            <artifactId>spring-kafka</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.kafka</groupId>
            <artifactId>spring-kafka-test</artifactId>
            <scope>test</scope>
        </dependency>
</dependencies>
```

To send events, we can use the `KafkaTemplate` provided by spring.
```java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;
import java.util.concurrent.CompletableFuture;

@Service
public class MyPublisher {
    private static final Logger log = LoggerFactory.getLogger(MyPublisher.class);
    private final KafkaTemplate<String, Object> kafkaTemplate;

    public MyPublisher(KafkaTemplate<String, Object> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
    }

    public CompletableFuture<Void> sendToTopic(String message) {
        log.info("sendToTopic - message: {}", message);
        return kafkaTemplate.send("mytopic", message)
                .thenAccept(res -> {
                    log.info("sendToTopic - message: {}, done", message);
                }).exceptionally(err -> {
                    log.warn("sendToTopic - message: {}, error: {}", message, err);
                    return null;
                });
    }
}

```

We can test our service with an embedded kafka instance.
```java
package com.mih.training.invoice.events;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.kafka.KafkaAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.kafka.test.context.EmbeddedKafka;

import java.util.concurrent.ExecutionException;

@EmbeddedKafka(topics = "mytopic")
@SpringBootTest(properties = "spring.kafka.bootstrap-servers=${spring.embedded.kafka.brokers}", classes = {MyPublisher.class, KafkaAutoConfiguration.class})
class MyPublisherTest {

    @Autowired
    MyPublisher myPublisher;

    @Test
    public void test() throws ExecutionException, InterruptedException {
        myPublisher.sendToTopic("test").get();
    }

}

```
Consume events:

```java
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.CompletableFuture;

@Service
public class MyConsumer {
    private static final Logger log = LoggerFactory.getLogger(MyConsumer.class);

    @KafkaListener(groupId = "group-1", topics = "mytopic")
    public void onMessage(ConsumerRecord<String, String> message) {
        log.info("onMessage -  received message: " + message);
    }
}

```

```text
2022-12-12T14:51:32.839+02:00  INFO 7153 --- [ntainer#0-0-C-1] c.m.events.MyConsumer   : onMessage -  received message: ConsumerRecord(topic = mytopic, partition = 0, leaderEpoch = 0, offset = 0, CreateTime = 1670849477934, serialized key size = -1, serialized value size = 4, headers = RecordHeaders(headers = [], isReadOnly = false), key = null, value = test)
```

In our app create a new file named: `Dockerfile` that starts our application.

```text
FROM amazoncorretto:17-al2022-jdk

COPY target/lib /app/lib
COPY target/classes /app/classes

EXPOSE 8080 8080

ENTRYPOINT ["java", "-cp", "/app/classes:/app/lib/*", "<main-class-full-name>"]
```

Create a `Run Configuration` to start the application as a container connected to the docker sandbox.
Don't forget to add `--network sandbox_default` to allow your new container to connect to kafka.

_Depending on the folder name you used, the network may be called differently._

### Configuration

We run the application with the docker profile and use docker specific properties from `application-docker.yaml`
```yaml
spring:
  kafka:
    properties:
      schema.registry.url: http://schema-registry:8091
    producer:
      value-serializer: io.confluent.kafka.serializers.KafkaAvroSerializer
      properties:
        schema.registry.url: http://schema-registry:8091
    bootstrap-servers: kafka:9092
```

### Avro messages
We can send Avro messages from our application. To do this, instead of sending simple string payloads we switch to a new serializer.

```xml
        <dependency>
            <groupId>io.confluent</groupId>
            <artifactId>kafka-streams-avro-serde</artifactId>
            <version>${confluent.version}</version>
        </dependency>
        <dependency>
            <groupId>io.confluent</groupId>
            <artifactId>kafka-schema-registry-client</artifactId>
            <version>${confluent.version}</version>
        </dependency>
        <dependency>
            <groupId>io.confluent</groupId>
            <artifactId>kafka-avro-serializer</artifactId>
            <version>${confluent.version}</version>
        </dependency>
        <dependency>
            <groupId>org.apache.avro</groupId>
            <artifactId>avro</artifactId>
            <version>1.11.0</version>
        </dependency>

        <repositories>
        <repository>
            <id>confluent</id>
            <url>https://packages.confluent.io/maven</url>
        </repository>
        </repositories>
```

Let's create our first avro message: `src/main/resources/avro/mytopic/InvoiceEvent.avsc`

```json
{
    "doc": "Internal representation of a paid invoice",
    "type": "record",
    "name": "MyEvent",
    "namespace": "com.mih.training.invoice.events",
    "fields": [
        {
            "doc": "Invoice Number",
            "name": "invoiceNumber",
            "default": null,
            "type": [
                "null",
                "string"
            ]
        },
        {
            "doc": "Invoice Date",
            "name": "invoiceDate",
            "default": null,
            "type": [
                "null",
                "long"
            ]
        },
        {
            "doc": "Total Amount Due",
            "name": "amoundDue",
            "default": null,
            "type": [
                "null",
                "double"
            ]
        }
    ]
}

```
To be able to use Java classes created from the avro files, we can use a plugin
```xml

<plugins>
        <plugin>
        <groupId>org.apache.avro</groupId>
        <artifactId>avro-maven-plugin</artifactId>
        <version>1.9.0</version>
        <executions>
            <execution>
                <phase>pre-clean</phase>
                <goals>
                    <goal>schema</goal>
                </goals>
                <configuration>
                    <sourceDirectory>${project.basedir}/src/main/resources/avro</sourceDirectory>
                    <includes>
                        <include>**/*.avsc</include>
                    </includes>
                    <outputDirectory>${project.basedir}/src/main/java</outputDirectory>
                    <imports>
                        <import>
                            ${project.basedir}/src/main/resources/avro/mytopic/InvoiceEvent.avsc
                        </import>
                    </imports>
                    <stringType>String</stringType>
                </configuration>
            </execution>
        </executions>
        </plugin>
</plugins>
```

Run `mvn clean install`.

Check `com.mih.training.invoice.events.InvoiceEvent` was generated.

Update publisher and consumer with the new payload type.

## Calling another service

Enable Spring Cloud
```xml
...
<spring-cloud.version>2022.0.0-RC2</spring-cloud.version>
...
`    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>org.springframework.cloud</groupId>
                <artifactId>spring-cloud-dependencies</artifactId>
                <version>${spring-cloud.version}</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>
```

Let's consume the endpoints described by this interface.

Add `spring-cloud-starter-contract-stub-runner`
```xml
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-contract-stub-runner</artifactId>
            <scope>test</scope>
        </dependency>
```
Http clients: RestTemplate, WebClient, HttpClient, OkHttp, Finagle etc

Add `Finagle`

```xml
        <dependency>
            <groupId>com.twitter</groupId>
            <artifactId>finagle-core_2.13</artifactId>
            <version>20.4.0</version>
        </dependency>
        <dependency>
            <groupId>com.twitter</groupId>
            <artifactId>finagle-http_2.13</artifactId>
            <version>20.4.0</version>
        </dependency>
```

Configure Finagle to call the remote service:

```java
@Configuration
public class FinagleConfig {
  private static final Logger log = LoggerFactory.getLogger(FinagleConfig.class);

  @Bean
  public Service<Request, Response> httpClient(@Value("${wiremock.server.port:8080}") int port,
                                               @Value("${global-timeout:5000}") int globalTimeout,
                                               @Value("${request-timeout:1000}") int requestTimeout) {

    Duration timeoutDuration = Duration.fromMilliseconds(globalTimeout);
    final TimeoutFilter<Request, Response> timeoutFilter = new TimeoutFilter<>(
            timeoutDuration,
            new GlobalRequestTimeoutException(timeoutDuration),
            DefaultTimer.getInstance()
    );

    Stream<Duration> backoff = Backoff.exponentialJittered(Duration.fromMilliseconds(100), Duration.fromMilliseconds(30_000));
    RetryExceptionsFilter<Request, Response> rt = new RetryExceptionsFilter<>(
            RetryPolicy.backoffJava(Backoff
                            .toJava(backoff),
                    RetryPolicy.TimeoutAndWriteExceptionsOnly()), HighResTimer.Default(), NullStatsReceiver.get());

    RetryBudget budget = RetryBudgets.newRetryBudget(Duration.fromMilliseconds(1000), 10, 1);
    Http.Client client = Http.client()
            .withRetryBudget(budget)
            .withRetryBackoff(backoff)
            .withRequestTimeout(Duration.fromMilliseconds(requestTimeout));

    return new LogFilter()
            .andThen(timeoutFilter)
            .andThen(rt)
            .andThen(client.newService(":" + port));

  }
}
```

Deserialize everything into an `Account`:
```java
public record Account(String id, String name) {
}
```

Create a service `AccountService` to get the accounts
```java

@Component
public class AccountService {
    private static final Logger log = LoggerFactory.getLogger(AccountService.class);
    private final Service<Request, Response> httpClient;
    private final ObjectMapper mapper;

    public AccountService(Service<Request, Response> httpClient, ObjectMapper mapper) {
        this.httpClient = httpClient;
        this.mapper = mapper;
    }

    public CompletableFuture<List<Account>> getAccounts() {

        Request request = Request.apply(Method.Get(), "/v2/accounts");
        request.host("localhost");
        Future<Response> response = httpClient.apply(request);

        return response.toCompletableFuture()
                .thenCompose(r -> {
                    Response res = (Response) r;
                    log.debug("getAccounts - received: {}, body: {}", res, res.contentString());
                    if (res.status() != Status.Ok()) {
                        return CompletableFuture.failedFuture(new IllegalStateException("could not get account"));
                    }
                    try {
                        List<Account> accounts = mapper.readValue(res.contentString(), new TypeReference<>() {});
                        return CompletableFuture.completedFuture(accounts);
                    } catch (JsonProcessingException e) {
                        log.error("getAccounts - error deserializing response", e);
                        return CompletableFuture.failedFuture(e);
                    }
                });
    }
}
```

Add mocks to `src/main/resources/mappings/accounts.json`
```json
{
  "request": {
    "method": "GET",
    "url": "/v2/accounts"
  },
  "response": {
    "status": 200,
    "headers": {
      "Content-Type": "application/json",
      "Cache-Control": "no-cache"
    },
    "fixedDelayMilliseconds": 500,
    "bodyFileName": "accounts.json"
  }
}
```
Add to `src/main/resources/__files/accounts.json`
```json
[
  {
    "id": "123",
    "name": "Account name 12312312"
  }
]
```
In a similar way, to the same for `Balance`:
```json
{
  "request": {
    "method": "GET",
    "url": "/v2/accounts/123/balance"
  },
  "response": {
    "status": 200,
    "delayDistribution": {
      "type": "lognormal",
      "median": 1000,
      "sigma": 0.4
    },
    "headers": {
      "Content-Type": "application/json",
      "Cache-Control": "no-cache"
    },
    "bodyFileName": "balance.json"
  }
}

```
With content `balance.json`:
```json
{
  "currency": "EUR",
  "value": 99.99
}

```

And the same for transactions:
```json
[
  {
    "id": "id-12345",
    "name": "Transaction 123r5432",
    "value": 5.99
  },
  {
    "id": "id-565556",
    "name": "Transaction name 12312312",
    "value": 11.10
  },
  {
    "id": "id-43543534",
    "name": "Transaction name 12312312",
    "value": 23.99
  }
]

```

Write the first test:

```java
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
@AutoConfigureMockMvc
@AutoConfigureWireMock(port = 0)
class AccountServiceTest {

    @Autowired
    AccountService service;

    @Test
    public void test() throws ExecutionException, InterruptedException {
        assertNotNull(service.getAccounts()
                .get());

    }

}
```
