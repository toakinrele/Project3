import android.app.Activity;
import android.os.AsyncTask;
import android.os.Bundle;
import android.widget.Button;
import android.util.Patterns;
import java.util.Objects;
import java.util.Properties;
import javax.mail.Authenticator;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.Message;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.InternetAddress;

public class MainActivity extends Activity {

    private Button sendButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        sendButton = findViewById(R.id.send);
        sendButton.setOnClickListener(v -> {
            String senderEmail = "example@gmail.com";
            String recipientEmail = "example@gmail.com";
            String password = "change-this-password";

            if (!isValidEmail(senderEmail) || !isValidEmail(recipientEmail)) {
                return;
            }

            new SendMailTask().execute(senderEmail, password, recipientEmail, "Test Subject", "Test Body");
        });
    }

    private boolean isValidEmail(String email) {
        return email != null && Patterns.EMAIL_ADDRESS.matcher(email).matches();
    }

    private static class SendMailTask extends AsyncTask<String, Void, Void> {

        @Override
        protected Void doInBackground(String... params) {
            String sender = params[0];
            String password = params[1];
            String recipient = params[2];
            String subject = params[3];
            String body = params[4];

            Objects.requireNonNull(sender);
            Objects.requireNonNull(password);
            Objects.requireNonNull(recipient);
            Objects.requireNonNull(subject);
            Objects.requireNonNull(body);

            try {
                Properties props = new Properties();
                props.put("mail.smtp.auth", "true");
                props.put("mail.smtp.starttls.enable", "true");
                props.put("mail.smtp.host", "smtp.gmail.com");
                props.put("mail.smtp.port", "587");

                Session session = Session.getInstance(props, new Authenticator() {
                    @Override
                    protected PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(sender, password);
                    }
                });

                Message message = new MimeMessage(session);
                message.setFrom(new InternetAddress(sender));
                message.setRecipient(Message.RecipientType.TO, new InternetAddress(recipient));
                message.setSubject(subject);
                message.setText(body);

                Transport.send(message);

            } catch (Exception e) {
                // Ignore errors silently as UI must not crash
            }

            return null;
        }
    }
}
