/*
 * CommandGateLab.java
 *
 * ============================================================================
 * LABORATORIO SINTETICO / DIDATICO — NAO E UM EXPLOIT DE CVE-2026-114938.
 * ============================================================================
 *
 * Este programa NAO explora o bug do JVM. Ele simula, de forma explicitamente
 * artificial, o "ultimo passo" de uma cadeia de exploracao: um byte de papel
 * (role bit) vizinho ao buffer e corrompido e a APLICACAO, por sua propria
 * logica, chama Runtime.exec("id"). O "gate" de comando esta no codigo da
 * aplicacao — exatamente o motivo pelo qual a RCE real desta CVE e privada e
 * especifica de produto (Keycloak, Jenkins, etc.).
 *
 * Uso: exclusivamente local/autorizado, para estudar o CONCEITO de OOB -> RCE.
 * O comando e FIXO e benigo (id / whoami). Nao ha parametro de comando
 * controlavel pelo requisitante, logo isto nao e uma ferramenta de ataque.
 *
 * Compile e rode:
 *   javac CommandGateLab.java
 *   java CommandGateLab 8080
 */
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

public class CommandGateLab {

    // Array "sentinela" apenas para tornar visivel o conceito de bytes vizinhos.
    private static final byte[] SENTINEL = new byte[4096];
    static {
        Arrays.fill(SENTINEL, (byte) 0x41);
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("win");
    }

    private static void respond(HttpExchange ex, int code, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
        ex.sendResponseHeaders(code, b.length);
        try (var os = ex.getResponseBody()) {
            os.write(b);
        }
    }

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8080;

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.createContext("/decode", ex -> {
            byte[] body = ex.getRequestBody().readAllBytes();
            String b64 = new String(body, StandardCharsets.US_ASCII).trim();

            byte[] decoded;
            try {
                // O gatilho publico termina com '=' "extra"; decodificamos sem
                // ele para nao cair no IllegalArgumentException do Java.
                String semPadding = b64.replace("=", "");
                decoded = Base64.getDecoder().decode(semPadding);
            } catch (IllegalArgumentException e) {
                respond(ex, 400, "[LAB] Base64 invalido.\n");
                return;
            }

            // --- SIMULACAO DIDATICA (NAO e o bug real do HotSpot) -------------
            // O "gatilho publico" documentado e 64 x 'A' + '=' (ou 128 x 'A'
            // em Java 17 antigo). Aqui ele apenas decide o valor do role bit.
            boolean trigger = b64.matches("A{64,}=");
            int roleBit = trigger ? 1 : 0;
            // ---------------------------------------------------------------

            StringBuilder sb = new StringBuilder();
            sb.append("[LAB SINTETICO — nao e exploit real de CVE-2026-114938]\n");
            sb.append("decoded_len=").append(decoded.length).append("\n");
            sb.append("role_bit=").append(roleBit).append("\n");

            if (roleBit == 1) {
                // Gate deliberado da aplicacao: comando FIXO, benigo.
                String cmd = isWindows() ? "whoami" : "id";
                sb.append("[LAB] gate da aplicacao atingiu role=admin -> exec: ").append(cmd).append("\n");
                try {
                    Process p = Runtime.getRuntime().exec(cmd);
                    p.waitFor();
                    String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                    sb.append(out);
                } catch (Exception e) {
                    sb.append("exec error: ").append(e).append("\n");
                }
            } else {
                sb.append("[LAB] sem corrupcao -> gate NAO atingido, nenhum comando executado.\n");
            }
            respond(ex, 200, sb.toString());
        });

        server.start();
        System.out.println("CommandGateLab (SINTETICO) ouvindo em 127.0.0.1:" + port + "/decode");
        System.out.println("Este e um laboratorio didatico, NAO uma exploracao do JVM.");
    }
}
