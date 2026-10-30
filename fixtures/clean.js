const base = process.env.PAYPAL_ENV === 'live' ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com';
const secret = process.env.PAYPAL_CLIENT_SECRET;
const CATALOG = { 'sku-pro': { value: '100.00' } };
app.post('/create-order', (req,res)=>{ const i = CATALOG[req.body.sku]; res.json({value:i.value}); });
