const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');
const moment = require('moment');
const nodemailer = require('nodemailer');
require('dotenv').config();
const twilio = require('twilio');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());

// MySQL Database Connection
const db = mysql.createPool({
  connectionLimit: 1000,
  host: process.env.HOST,
  user: process.env.USER,
  password: process.env.PASSWORD,
  database: process.env.DBNAME,
  connectTimeout: 900000000, // Set a higher connection timeout (in milliseconds)
});



const accountSid = process.env.SID; // Replace with your Twilio Account SID
const authToken = process.env.AUTHTOKEN;   // Replace with your Twilio Auth Token
const client = twilio(accountSid, authToken);

db.on('connect', () => {
  console.log('Database connected successfully!');
});

// Handling connection error (e.g., connection lost)
db.on('error', (err) => {
  console.error('MySQL error:', err);
  if (err.code === 'PROTOCOL_CONNECTION_LOST') {
    console.log('Connection lost, reconnecting...');
    handleConnection(); // Retry the connection
  } else {
    console.error('Unexpected MySQL error:', err);
  }
});


const handleConnection = () => {
  db.getConnection((err, connection) => {
    if (err) {
      console.error('MySQL connection error:', err);
      if (err.code === 'PROTOCOL_CONNECTION_LOST') {
        console.log('Connection lost, attempting to reconnect...');
        setTimeout(handleConnection, 5000); // Retry after 5 seconds
      }
    } else {
      console.log('Database connected successfully');
      connection.release(); // Release the connection back to the pool
    }
  });
};


app.use(express.static(path.join(__dirname, 'public')));

// Default route to serve the index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

//login and register

app.post('/create', async (req, res) => {
    const { email, company_id, password } = req.body;

    // Input validation
    if (!email || !company_id || !password) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    try {
        // Check if the email is already registered
        db.query('SELECT * FROM User WHERE email = ?', [email], async (err, results) => {
            if (err) throw err;

            if (results.length > 0) {
                return res.status(400).json({ message: 'Email already exists.' });
            }

            // Hash the password
            const hashedPassword = await bcrypt.hash(password, 10);

            // Insert new admin into the database
            db.query(
                'INSERT INTO User (email, company_id, password) VALUES (?, ?, ?)',
                [email, company_id, hashedPassword],
                (err, result) => {
                    if (err) throw err;

                    res.status(201).json({ message: 'User account created successfully.' });
                }
            );
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error.' });
    }
});

// login

app.post('/login', (req, res) => {
    const { email, company_id, password } = req.body;
  
    // Input validation
    if (!email || !company_id || !password) {
      return res.status(400).json({ message: 'All fields are required.' });
    }
  
    try {
      // Check if admin exists in the database
      db.query(
        'SELECT * FROM Admin WHERE email = ? AND company_id = ?',
        [email, company_id],
        async (err, results) => {
          if (err) throw err;
  
          if (results.length === 0) {
            return res.status(401).json({ message: 'Invalid email, company ID, or password.' });
          }
  
          // Compare hashed password
          const admin = results[0];
          const isPasswordValid = await bcrypt.compare(password, admin.password);
  
          if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid email, company ID, or password.' });
          }
  
          // Successful login
          res.status(200).json({ message: 'Login successful!' });
        }
      );
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Server error.' });
    }
  });

//dashboard

app.get('/dashboard-data/:companyId', (req, res) => {
  const companyId = req.params.companyId;

  const query = `
    SELECT
        COUNT(*) AS totalRaised,
        SUM(CASE WHEN status = 'Resolved' THEN 1 ELSE 0 END) AS totalResolved,
        SUM(CASE WHEN status IN ('Pending', 'In Progress') THEN 1 ELSE 0 END) AS totalPendingInProgress,
        AVG(CASE WHEN resolved_at IS NOT NULL THEN DATEDIFF(resolved_at, created_at) ELSE NULL END) AS avgResolutionTime
    FROM complaints
    WHERE company_id = ?
`;


  db.query(query, [companyId], (err, results) => {
      if (err) {
          console.error(err);
          res.status(500).json({ message: 'Error fetching dashboard data', error: err });
      } else {
          const data = results[0];
          res.status(200).json({
              totalRaised: data.totalRaised || 0,
              totalResolved: data.totalResolved || 0,
              totalPendingInProgress: data.totalPendingInProgress || 0,
              avgResolutionTime: data.avgResolutionTime ? Number(data.avgResolutionTime): 0
          });
      }
  });
});

app.post('/submit-complaint', (req, res) => {
    const complaintData = req.body;

    // Use the provided createdAt from the frontend (already in IST format)
    const { companyId, fullName, email, phone, address, productId, productName, complaintType, keyProblem, issueDescription, createdAt } = complaintData;

    // SQL query to insert the complaint into the database
    const sqlQuery = `
        INSERT INTO complaints (company_id, full_name, email, phone, address, product_id, product_name, complaint_type, key_problem, issue_description, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    const formattedDate = moment(complaintData.createdAt, 'DD-MM-YYYY HH:mm:ss').format('YYYY-MM-DD HH:mm:ss');


    const values = [
        companyId,
        fullName,
        email,
        phone,
        address,
        productId,
        productName,
        complaintType,
        keyProblem,
        issueDescription,
        formattedDate // Insert the IST time received from the frontend
    ];

    db.query(sqlQuery, values, (err, result) => {
        if (err) {
          console.log(err);
            res.status(500).json({ message: 'Error saving complaint', error: err });
        } else {
            const complaintId = result.insertId;
            console.log(`Complaint submitted successfully!, ComplaintId : ${complaintId}`);
            res.status(200).json({ message: 'Complaint submitted successfully!', complaintId: complaintId });
        }
    });
});

// fetch complaint table

app.get('/get-complaints/:companyId', (req, res) => {
  const companyId = req.params.companyId;
  const { search, status } = req.query;

  let query = 'SELECT * FROM complaints WHERE company_id=?'; // Base query
  const params = [companyId];

  // Add filtering conditions if provided
  if (search) {
      query += ' AND (id LIKE ? OR product_name LIKE ?)';
      params.push(`%${search}%`, `%${search}%`);
  }

  if (status) {
      query += ' AND status = ?';
      params.push(status);
  }

  db.query(query, params, (err, results) => {
      if (err) {
          console.error(err);
          res.status(500).send('Error fetching complaints');
      } else {
          res.json(results);
      }
  });
});

// Route to update complaint status
app.patch('/complaints/:id/withdraw', (req, res) => {
  const complaintId = req.params.id;

  // Validate the input (optional)
  if (!req.body.status) {
      return res.status(400).json({ message: 'Status is required' });
  }

  // SQL query to update the status of the complaint in the database
  const query = 'UPDATE complaints SET status = ? WHERE id = ?';
  
  db.execute(query, [req.body.status || 'Withdrawn', complaintId], (err, result) => {
      if (err) {
          console.error(err);
          return res.status(500).json({ message: 'Error updating complaint status' });
      }

      // Check if any rows were affected (i.e., complaint exists)
      if (result.affectedRows > 0) {
          console.log(`Complaint Id: ${complaintId}, Complaint withdrawn successfully`);
          res.status(200).json({ message: `Complaint Id: ${complaintId}, Complaint withdrawn successfully` });
      } else {
        console.log(`Complaint Id: ${complaintId}, Complaint not found`);
          res.status(404).json({ message: `Complaint Id: ${complaintId}, Complaint not found` });
      }
  });
});

//followups

app.get('/complaint-details/:complaintId', (req, res) => {
  const complaintId = req.params.complaintId;

  // SQL query to fetch complaint details
  const complaintQuery = `
      SELECT * 
      FROM complaints
      WHERE id = ?
  `;

  // SQL query to fetch follow-ups sorted by followup_no
  const followupQuery = `
      SELECT * 
      FROM followbacks
      WHERE complaint_id = ?
      ORDER BY followback_number ASC
  `;

  // Execute queries
  db.query(complaintQuery, [complaintId], (err, complaintResults) => {
      if (err) {
          console.error(err);
          return res.status(500).json({ message: 'Error fetching complaint details', error: err });
      }

      // Fetch follow-ups
      db.query(followupQuery, [complaintId], (err, followupResults) => {
          if (err) {
              console.error(err);
              return res.status(500).json({ message: 'Error fetching follow-up details', error: err });
          }

          // Send both complaint and follow-up details
          res.status(200).json({
              complaint: complaintResults[0] || null,
              followups: followupResults || []
          });
      });
  });
});



app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT} `);
  });