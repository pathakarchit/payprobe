import express from 'express';
const app = express();
app.use(express.json());
app.post('/paypal/webhook', (req, res) => {
  const event_type = req.body.event_type;
  if (event_type === 'PAYMENT.CAPTURE.COMPLETED') {
    grant(req.body.resource.id); // accepts any event blindly
  }
  res.sendStatus(200);
});
function grant(id){}
