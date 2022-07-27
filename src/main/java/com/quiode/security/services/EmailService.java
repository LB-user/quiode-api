package com.quiode.security.services;

import com.quiode.models.User;
import com.quiode.security.jwt.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.security.authentication.AuthenticationManager;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import com.quiode.security.jwt.JwtUtils;

@Service
public class EmailService {
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    public JavaMailSender emailSender;
    @Autowired
    JwtUtils jwtUtils;
    public EmailService(JavaMailSender javaMailSender) {
        this.emailSender = javaMailSender;
    }

    @ResponseBody
    public String sendRegisterMail(User user, String randomCode) throws MessagingException {

        String toAddress = user.getEmail();
        String fromAddress = "fake@gmail.com";
        String subject = "Veuillez confirmer votre adresse email";
        String content = "[[name]],<br>"
                + "Veuillez utiliser le code suivant pour confirmer votre adresse email: [[randomCode]].<br>"
                + "Merci,<br>"
                + "la Team Quiode.";

        MimeMessage message = emailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message);

        helper.setFrom(fromAddress);
        helper.setTo(toAddress);
        helper.setSubject(subject);

        content = content.replace("[[name]]", user.getUsername());
        content = content.replace("[[randomCode]]", randomCode);

        helper.setText(content, true);

        emailSender.send(message);

        return "Email sent";
    }

    @ResponseBody
    public String sendForgotPasswordMail(User user, String resetToken) throws MessagingException {

        String link = "http://localhost:4200" + "/reset?token=" +resetToken;
        String toAddress = user.getEmail();
        String fromAddress = "fake@gmail.com";
        String subject = "Réinitialisation du mot de passe";
        String content = "[[name]],<br>"
                + "Veuillez utiliser le lien suivant pour modifier votre mot de passe: <a href='[[link]]'>Lien de réinitialisation du mot de passe</a>"
                + "Merci,<br>"
                + "la Team Quiode.";

        MimeMessage message = emailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message);

        helper.setFrom(fromAddress);
        helper.setTo(toAddress);
        helper.setSubject(subject);

        content = content.replace("[[name]]", user.getUsername());
        content = content.replace("[[link]]", link);

        helper.setText(content, true);

        emailSender.send(message);

        return "Email sent";
    }

}