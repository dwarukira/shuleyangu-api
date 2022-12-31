use lettre::transport::smtp::authentication::Credentials;
use lettre::{
    message::{header, MultiPart, SinglePart},
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};

pub async fn send_email(
    email: &str,
    subject: &str,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let smtp_credentials =
        Credentials::new("support@cladfy.com".to_string(), "jkmobh101".to_string());

    let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay("mail.privateemail.com")?
        .credentials(smtp_credentials)
        .build();

    let from = "Shulecoms <support@cladfy.com>";
    let to = email;
    let subject = subject;
    let body = message;

    send_email_smtp(&mailer, from, to, subject, body).await
}

async fn send_email_smtp(
    mailer: &AsyncSmtpTransport<Tokio1Executor>,
    from: &str,
    to: &str,
    subject: &str,
    body: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let email = Message::builder()
        .from(from.parse()?)
        .to(to.parse()?)
        .subject(subject)
        .multipart(
            MultiPart::alternative()
                .singlepart(
                    SinglePart::builder()
                        .header(header::ContentType::TEXT_PLAIN)
                        .body(String::from(body)),
                )
                .singlepart(
                    SinglePart::builder()
                        .header(header::ContentType::TEXT_HTML)
                        .body(String::from(body)),
                ),
        )?;
    mailer.send(email).await?;

    Ok(())
}
