from django.core.exceptions import ValidationError
from django.test import TestCase
from django.contrib.auth import get_user_model


class ModelTest(TestCase):
    def test_create_user_with_email_successful(self):
        """Test creating a new user with an email is successful"""
        email = 'ls.dancer@gmail.com'
        password = 'Mars555'
        user = get_user_model().objects.create_user(
            email=email,
            password=password
        )
        self.assertEqual(user.email, email)
        self.assertTrue(user.check_password(password))

    def test_new_user_email_normalized(self):
        """Test the email for a new user is normalized"""
        email = 'Test@blaBLA.coM'
        email_norm = 'Test@blabla.com'
        user = get_user_model().objects.create_user(email, 'test1234')
        self.assertEqual(user.email, email_norm)

    def test_new_user_invalid_email(self):
        """Test creating user with badly formed email raises error"""
        with self.assertRaises(ValidationError):
            get_user_model().objects.create_user(
                'pasha@some#strange$box', 'test123'
            )

    def test_new_user_missing_email(self):
        """Test creating user with badly formed email raises error"""
        with self.assertRaises(ValidationError):
            get_user_model().objects.create_user(None, 'test123')

    def test_create_new_superuser(self):
        """Test creating a new superuser"""
        user = get_user_model().objects.create_superuser(
            'pasha@domain.com',
            'pwd1234'
        )
        self.assertTrue(user.is_superuser)
        self.assertTrue(user.is_staff)
