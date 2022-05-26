package com.quiode.security.services;

import com.quiode.models.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

@Service
public class EmailService {

    @Autowired
    public JavaMailSender emailSender;

    public EmailService(JavaMailSender javaMailSender) {
        this.emailSender = javaMailSender;
    }

    @ResponseBody
    public String sendRegisterMail(User user) throws MessagingException {

        String toAddress = user.getEmail();
        String fromAddress = "fake@gmail.com";
        String subject = "Veuillez confirmer votre adresse email";
        String content = "[[name]],<br>"
                + "Veuillez utiliser le code suivant pour confirmer votre adresse email: [[code]].<br>"
                + "Merci,<br>"
                + "la Team Quiode.";

        MimeMessage message = emailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message);

        helper.setFrom(fromAddress);
        helper.setTo(toAddress);
        helper.setSubject(subject);

        content = content.replace("[[name]]", user.getUsername());
        content = content.replace("[[code]]", user.getVerificationCode());

        helper.setText(content, true);

        emailSender.send(message);

        return "Email sent";
    }

}