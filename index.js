const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const z = require('zod');
require('dotenv').config(); 

const app = express();
app.use(bodyParser.json());


mongoose.connect(process.env.MONGODB_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})

.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('Error connecting to MongoDB:', err));

/*const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => console.log('Connected to MongoDB'));
*/

// Book Schema
const bookSchema = new mongoose.Schema({
  title: String,
  author: String,
  publicationYear: Number,
});

const Book = mongoose.model('books', bookSchema);

// User schema
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
});
const User = mongoose.model('users', userSchema);

// zod schemas for input validation
const bookSchemaZod = z.object({
  title: z.string().min(1),
  author: z.string().min(1),
  publicationYear: z.number().int().min(1000).max(new Date().getFullYear()),
});

const userSchemaZod = z.object({
  username: z.string().min(1),
  password: z.string().min(6),
});

// Authentication middleware
function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
        console.log(err);
        return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
}

// Generate Token
function generateAccessToken(user) {
  let sign = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET);
  return sign;
}

// User registration Endpoint
app.post('/register', async (req, res) => {
  try {
    const validatedData = userSchemaZod.parse(req.body);
    const hashedPassword = await bcrypt.hash(validatedData.password, 10);
    const user = new User({
      username: validatedData.username,
      password: hashedPassword,
    });
    await user.save();
    res.status(201).send('User is registered successfully');
  } catch (error) {
    res.status(400).send(error.errors);
  }
});

// User Login Endpoint
app.post('/login', async (req, res) => {
  const user = await User.findOne({ username: req.body.username });
  if (!user) return res.status(400).send('Not found user');

  try {
    if (bcrypt.compare(req.body.password, user.password)) {
      const accessToken = generateAccessToken({ username: user.username });
      res.json({ accessToken: accessToken });
    } else {
      res.status(401).send('Invalid password');
    }
  } catch {
    res.status(500).send('Login failed');
  }
});


// CRUD operations for managing books

// Create a new book
app.post('/books', authenticateToken, async (req, res) => {
  try {
    const validatedData = bookSchemaZod.parse(req.body);
    const book = new Book(validatedData);
    const newBook = await book.save();
    res.status(201).json(newBook);
  } catch (error) {
    res.status(400).send(error.errors);
  }
});

// Retrieve all books or filter by author/publication year
app.get('/books', authenticateToken, async (req, res) => {
  try {
    let query = {};
    if (req.query.author) query.author = req.query.author;
    if (req.query.publicationYear)
      query.publicationYear = req.query.publicationYear;
    const books = await Book.find(query)
    res.json(books);
    
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// Update a book by ID
app.put('/books/:id', authenticateToken, async (req, res) => {
  try {
    const validatedData = bookSchemaZod.parse(req.body);
    const book = await Book.findByIdAndUpdate(req.params.id, validatedData, {
      new: true,
    });
    res.json(book);
  } catch (error) {
    res.status(400).send(error.errors);
  }
});

// Delete a book by ID
app.delete('/books/:id', authenticateToken, async (req, res) => {
  try {
    await Book.findByIdAndDelete(req.params.id);
    res.sendStatus(204);
  } catch (err) {
    res.status(400).send(err.message);
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
