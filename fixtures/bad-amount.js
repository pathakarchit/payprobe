app.post('/create-order', async (req, res) => {
  const order = await paypal.orders.create({
    intent: 'CAPTURE',
    purchase_units: [{ amount: { currency_code: 'USD', value: req.body.amount } }],
  });
  res.json(order);
});
