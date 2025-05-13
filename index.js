require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json());

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

app.post('/signup', async (req, res) => {
  const { email, password } = req.body;

  const { data: existingUser } = await supabase
    .from('users')
    .select('email')
    .eq('email', email)
    .single();

  if (existingUser) {
    return res.status(400).json({ error: 'Usuário já cadastrado.' });
  }

  const { data: signUpData, error: signUpError } = await supabase.auth.signUp({
    email,
    password,
  });

  if (signUpError) {
    return res.status(400).json({ error: signUpError.message });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const { error: userError } = await supabase
    .from('users')
    .insert([
      {
        id: signUpData.user.id,
        email,
        senha: hashedPassword,
        user_name: email,
        is_admin: false,
      },
    ]);

  if (userError) {
    return res.status(400).json({ error: userError.message });
  }

  res.status(201).json({ message: 'Usuário cadastrado com sucesso.' });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const { data: signInData, error: signInError } = await supabase.auth.signInWithPassword({
    email,
    password,
  });

  if (signInError) {
    return res.status(400).json({ error: signInError.message });
  }

  res.status(200).json({
    message: 'Login realizado com sucesso.',
    session: signInData.session,
    user: signInData.user,
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
