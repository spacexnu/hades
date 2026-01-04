-- Add suspicious dictionary storage with moderation status

CREATE TABLE IF NOT EXISTS suspicious_dictionary (
    id SERIAL PRIMARY KEY,
    phrase TEXT NOT NULL,
    language VARCHAR(8) NOT NULL DEFAULT 'unknown',
    category VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'approved',
    source VARCHAR(32) NOT NULL DEFAULT 'seed',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS suspicious_dictionary_phrase_category_uq
    ON suspicious_dictionary (lower(phrase), category);

CREATE INDEX IF NOT EXISTS suspicious_dictionary_category_status_idx
    ON suspicious_dictionary (category, status);

INSERT INTO suspicious_dictionary (phrase, language, category, status, source) VALUES
    -- URL keywords
    ('login', 'en', 'url_keyword', 'approved', 'seed'),
    ('verify', 'en', 'url_keyword', 'approved', 'seed'),
    ('update', 'en', 'url_keyword', 'approved', 'seed'),
    ('secure', 'en', 'url_keyword', 'approved', 'seed'),
    ('bank', 'en', 'url_keyword', 'approved', 'seed'),
    ('pagmei', 'pt', 'url_keyword', 'approved', 'seed'),
    ('regulariza', 'pt', 'url_keyword', 'approved', 'seed'),
    ('regularize', 'pt', 'url_keyword', 'approved', 'seed'),
    ('imediato', 'pt', 'url_keyword', 'approved', 'seed'),
    ('pagamento', 'pt', 'url_keyword', 'approved', 'seed'),
    ('boleto', 'pt', 'url_keyword', 'approved', 'seed'),
    ('pix', 'pt', 'url_keyword', 'approved', 'seed'),
    ('cnpj', 'pt', 'url_keyword', 'approved', 'seed'),
    ('cpf', 'pt', 'url_keyword', 'approved', 'seed'),
    -- HTML title phrases
    ('verify your account', 'en', 'html_title', 'approved', 'seed'),
    ('account suspended', 'en', 'html_title', 'approved', 'seed'),
    ('urgent action required', 'en', 'html_title', 'approved', 'seed'),
    ('security alert', 'en', 'html_title', 'approved', 'seed'),
    ('confirm your identity', 'en', 'html_title', 'approved', 'seed'),
    ('update payment', 'en', 'html_title', 'approved', 'seed'),
    ('expired session', 'en', 'html_title', 'approved', 'seed'),
    ('login verification', 'en', 'html_title', 'approved', 'seed'),
    ('verifique sua conta', 'pt', 'html_title', 'approved', 'seed'),
    ('conta suspensa', 'pt', 'html_title', 'approved', 'seed'),
    ('acao imediata', 'pt', 'html_title', 'approved', 'seed'),
    ('alerta de seguranca', 'pt', 'html_title', 'approved', 'seed'),
    ('confirmar identidade', 'pt', 'html_title', 'approved', 'seed'),
    ('atualizar pagamento', 'pt', 'html_title', 'approved', 'seed'),
    ('sessao expirada', 'pt', 'html_title', 'approved', 'seed'),
    ('verificacao de login', 'pt', 'html_title', 'approved', 'seed'),
    ('pagamento pendente', 'pt', 'html_title', 'approved', 'seed'),
    -- HTML phishing keywords
    ('click here to verify', 'en', 'html_keyword', 'approved', 'seed'),
    ('account will be closed', 'en', 'html_keyword', 'approved', 'seed'),
    ('immediate action required', 'en', 'html_keyword', 'approved', 'seed'),
    ('suspended account', 'en', 'html_keyword', 'approved', 'seed'),
    ('confirm your password', 'en', 'html_keyword', 'approved', 'seed'),
    ('update your information', 'en', 'html_keyword', 'approved', 'seed'),
    ('verify identity', 'en', 'html_keyword', 'approved', 'seed'),
    ('security breach', 'en', 'html_keyword', 'approved', 'seed'),
    ('unauthorized access', 'en', 'html_keyword', 'approved', 'seed'),
    ('click here immediately', 'en', 'html_keyword', 'approved', 'seed'),
    ('clique aqui para verificar', 'pt', 'html_keyword', 'approved', 'seed'),
    ('conta sera encerrada', 'pt', 'html_keyword', 'approved', 'seed'),
    ('acao imediata necessaria', 'pt', 'html_keyword', 'approved', 'seed'),
    ('conta suspensa', 'pt', 'html_keyword', 'approved', 'seed'),
    ('confirme sua senha', 'pt', 'html_keyword', 'approved', 'seed'),
    ('atualize suas informacoes', 'pt', 'html_keyword', 'approved', 'seed'),
    ('verifique sua identidade', 'pt', 'html_keyword', 'approved', 'seed'),
    ('violacao de seguranca', 'pt', 'html_keyword', 'approved', 'seed'),
    ('acesso nao autorizado', 'pt', 'html_keyword', 'approved', 'seed'),
    ('clique aqui imediatamente', 'pt', 'html_keyword', 'approved', 'seed'),
    ('pagamento pendente', 'pt', 'html_keyword', 'approved', 'seed'),
    ('regularizacao imediata', 'pt', 'html_keyword', 'approved', 'seed'),
    ('boleto', 'pt', 'html_keyword', 'approved', 'seed'),
    ('pix', 'pt', 'html_keyword', 'approved', 'seed'),
    -- Form actions
    ('login', 'en', 'form_action', 'approved', 'seed'),
    ('signin', 'en', 'form_action', 'approved', 'seed'),
    ('verify', 'en', 'form_action', 'approved', 'seed'),
    ('confirm', 'en', 'form_action', 'approved', 'seed'),
    ('update', 'en', 'form_action', 'approved', 'seed'),
    ('secure', 'en', 'form_action', 'approved', 'seed'),
    ('entrar', 'pt', 'form_action', 'approved', 'seed'),
    ('verificar', 'pt', 'form_action', 'approved', 'seed'),
    ('confirmar', 'pt', 'form_action', 'approved', 'seed'),
    ('atualizar', 'pt', 'form_action', 'approved', 'seed'),
    ('seguranca', 'pt', 'form_action', 'approved', 'seed'),
    ('pagamento', 'pt', 'form_action', 'approved', 'seed')
ON CONFLICT DO NOTHING;
