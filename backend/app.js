/* imports */
require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

// Config JSON response
app.use(express.json())

// Models
const User = require('./src/models/User')

// Open Route - Public Route
app.get('/', async (req, res) => {
  res.status(200).json({msg: "Bem vindo a nossa API!"})
})

// Private Route
app.get('/user/:id', checkToken, async (req, res) => {
  const { id } = req.params

  // Check if user exists
  const user = await User.findById(id, '-password')

  if (!user) {
    return res.status(404).json({
      msg: 'Usuário não encontrado'
    })
  }

  res.status(200).json({ user })
})

function checkToken(req, res, next) {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]

  if (!token) {
    return res.status(401).json({
      msg: 'Acesso negado'
    })
  }

  try {
    const secret = process.env.SECRET
    jwt.verify(token, secret)
    next()
  
  } catch (err) {
    res.status(400).json({
      msg: 'Token inválido'
    })
  }
}

// Register User
app.post('/auth/register', async (req, res) => {
  const { name, email, password, confirmPassword } = req.body

  // Validations
  if (!name) {
    return res.status(422).json({
      error: 'O nome é obrigatório'
    })
  }

  if (!email) {
    return res.status(422).json({
      error: 'O Email é obrigatório'
    })
  }

  if (!password) {
    return res.status(422).json({
      error: 'A senha é obrigatória'
    })
  }

  if (password !== confirmPassword) {
    return res.status(422).json({
      error: 'As senhas devem ser iguais'
    })
  }

  // Check if user exists
  const userExists = await User.findOne({
    email: email
  })

  if (userExists) {
    return res.status(422).json({
      error: 'Por favor, utilize outro email'
    })
  }

  // Create password
  const salt = await bcrypt.genSalt(12)
  const passwordHash = await bcrypt.hash(password, salt)

  // Create User
  const user = new User({
    name,
    email,
    password: passwordHash
  })

  try {
    await user.save()
    res.status(201).json({
      success: 'Usuário criado com sucesso'
    })

  } catch (err) {
    console.log(err)
    res.status(500).json({
      error: 'Ocorreu um erro no servidor, tente novamente mais tarde'
    })
  }
})

// Login User
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body

  if (!email) {
    return res.status(422).json({
      error: 'O Email é obrigatório'
    })
  }

  if (!password) {
    return res.status(422).json({
      error: 'A senha é obrigatória'
    })
  }

  // Check if user Exists
  const user = await User.findOne({
    email: email
  })

  if (!user) {
    return res.status(422).json({
      error: 'Email não encontrado'
    })
  }

  // Check if password match
  const checkPassword = await bcrypt.compare(password, user.password)

  if (!checkPassword) {
    return res.status(422).json({
      error: 'Senha incorreta'
    })
  }

  try {
    const secret = process.env.SECRET
    const token = jwt.sign({
      id: user._id
    }, secret)

    res.status(200).json({
      success: 'Autenticação realizada com sucesso',
      token
    })

  } catch (err) {
    console.log(err)
    res.status(500).json({
      error: 'Ocorreu um erro no servidor, tente novamente mais tarde'
    })
  }
})

// Credencials
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.k8gz07c.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`)
  .then((res) =>  {
    app.listen(3333)
    console.log('Conectou ao banco')
  })
  .catch((err) => console.log(err))
