require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

//Middleware
app.use(express.json());


//Models
const User = require('./models/User');

//Public route
app.get('/', (req, res) => {
    res.status(200).json({ msg: 'Bem vindo mufrend!' });
});

//Private router
app.get('/user/:id', checkToken, async (req, res) => {

    const id = req.params.id;

    const user = await User.findById(id, ['-password']);

    if (!user)
        return res.status(404).json({ text: 'Usuário não identificado' });

    res.status(200).json({ user });
});

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    console.log(req.headers);
    const token = authHeader;

    if (!token)
        return res.status(401).json({ text: 'Acesso negado!' });

    try {
        const secret = process.env.SECRET;

        jwt.verify(token, secret);

        next();
    } catch (error) {
        res.status(400).json({ text: "Token invalido!" });
    }
}

//Registrar User
app.post('/auth/register', async (req, res) => {

    const { name, email, password } = req.body;

    //validations
    if (!name)
        return res.status(422).json({ text: 'Preencha o nome' });

    if (!email)
        return res.status(422).json({ text: 'Preencha o email' });

    if (!password)
        return res.status(422).json({ text: 'Preencha a senha' });

    //check if user exist
    const userExist = await User.findOne({ email: email });

    if (userExist)
        return res.status(422).json({ text: 'Utilize outro email' });

    //create password
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    //create user
    const user = new User({
        name,
        email,
        password: passwordHash
    })

    try {

        await user.save();

        res.status(201).json({
            text: 'Usuário enviado com sucesso'
        })

    } catch (error) {
        console.log(error)
        res
            .status(500)
            .json({ text: 'Error no servidor' })
    }
})


//Login User
app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;

    //validations
    if (!email)
        return res.status(422).json({ text: 'Preencha o email' });

    if (!password)
        return res.status(422).json({ text: 'Preencha a senha' });

    //check if user exist
    const user = await User.findOne({ email: email });

    if (!user)
        return res.status(404).json({ text: 'Usuário não identificado' });

    const checkPassword = await bcrypt.compare(password, user.password);

    if (!checkPassword)
        return res.status(422).json({ text: 'Senha incorreta' });

    try {

        const secret = process.env.SECRET;

        const token = jwt.sign(
            {
                id: user._id
            },
            secret
        )

        res.status(200).json({
            text: 'Login realizado com sucesso!',
            token
        })

    } catch (error) {
        console.log(error)
        res
            .status(500)
            .json({ text: 'Error no servidor' })
    }
})


//Chama as credenciais
const dbUser = process.env.DB_USER;
const dbPass = process.env.DB_PASS;

mongoose
    .connect(`mongodb+srv://${dbUser}:${dbPass}@cluster0.eevfjmt.mongodb.net/?retryWrites=true&w=majority`)
    .then(() => {
        app.listen(4004);
        console.log('Conectou ao banco');
    })
    .catch((err) => console.log('Esse erro:', err))

