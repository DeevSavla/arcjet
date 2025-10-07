import express from 'express'

const app = express()

const port = 3000

app.use(express.json())
app.use(express.urlencoded())

app.listen(port , ()=>{
    console.log(`Server running on port ${port}`)
})