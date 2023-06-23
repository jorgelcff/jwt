require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bycript = require('bcrypt');


const app = express();
app.use(express.json());


// Models
const User = require('./models/User')

// Rota Pública

app.get('/', (req, res) => {
  res.status(200).json({ msg: 'Bem Vindo a nossa api.' })
})

// Rota Privada

app.get('/usuario/:id', checarToken, async (req, res) => {
  const id = req.params.id;

  // Checagem Usuário
  await User.findById(id, '-senha').then((result) => {
    return res.status(200).json(result);
  }).catch((err) => {
    return res.status(404).json({msg: 'Usuário não encontrado!', err});
  })
})

// Checar Token 

function checarToken (req, res, next){
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(" ")[1];


  if (!token){
    return res.status(401).json({msg: 'Acesso Negado!'})
  }

  try {

    const secret = process.env.SECRET;

    jwt.verify(token, secret);

    next();

  } catch(err){
    return res.status(400).json({msg: "Token Incorreto"})
  }
}


// Cadastro Usuário 

app.post('/auth/register', async (req, res) =>{

  const {nome, email, senha, confirmarSenha} = req.body;

  // Validações

  if (!nome){
    return res.status(422).json({msg: 'O nome é obrigatório!'});
  }

  if (!email){
    return res.status(422).json({msg: 'O email é obrigatório!'});
  }

  if (!senha){
    return res.status(422).json({msg: 'A senha é obrigatória!'});
  }

  if (senha !== confirmarSenha){
    return res.status(422).json({msg: 'As senhas não conferem!'});
  }

  // checagem de usuario 

  const usuarioExiste = await User.findOne({ email: email });

  if (usuarioExiste){
    return res.status(422).json({msg: 'Por favor, use outro email!'});
  }

  // criar senha
  
  const salt = await bycript.genSalt(12);
  const senhaHash = await bycript.hash(senha, salt);

  // criar usuario

  const user = new User({
    nome,
    email,
    senha: senhaHash,
  })

  try {

    await user.save();

    res.status(201).json({msg: 'Usuário criado com sucesso!'})


  } catch(err){
    console.log(err);
    res.status(500).json({msg: 'Aconteceu um erro no servidor, tente novamente mais tarde!'})
  }
})

// Login Usuário 

app.post('/auth/login',  async (req, res) =>{
  const {email, senha} = req.body;

  // Validações

  if (!email){
    return res.status(422).json({msg: 'O email é obrigatório!'});
  }

  if (!senha){
    return res.status(422).json({msg: 'A senha é obrigatória!'});
  }

  // Checagem Usuário

  
  const usuario = await User.findOne({ email: email });

  if (!usuario){
    return res.status(404).json({msg: 'Usuário não encontrado'});
  }

  // Checagem de senha válida

  const checarSenha = await bycript.compare(senha, usuario.senha);

  if (!checarSenha){
    return res.status(422).json({msg: 'Senha Incorreta!'});
  }

  try{
    const secret = process.env.SECRET;

    const token = jwt.sign({
        id: usuario.id,
      },
      secret,
    )

    res.status(200).json({msg: 'Autenticação realizada com sucesso', token})
  } catch(err){
    console.log(err);
    res.status(500).json({msg: 'Aconteceu um erro no servidor, tente novamente mais tarde!'})
  }

})



const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.gzyogon.mongodb.net/?retryWrites=true&w=majority`).then(() => {
  app.listen(3000);
  console.log('Conectou ao banco');
  })
  .catch((err) => console.log(err))



