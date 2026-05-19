-- Disable email confirmation for development
-- Run this in Supabase SQL Editor
-- NOTE: Re-enable for production!

UPDATE auth.users SET email_confirmed_at = NOW() WHERE email_confirmed_at IS NULL;
