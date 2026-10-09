import sqlite3
import os
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse

app = FastAPI()

# Inicialização de um banco de dados SQLite vulnerável.
def init_db():
    conn = sqlite3.connect("universidade.db")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS alunos (id INTEGER, nome TEXT, nota REAL, segredo TEXT)")
    cursor.execute("DELETE FROM alunos") # Limpa a base a cada restart
    cursor.execute("INSERT INTO alunos VALUES (1, 'Ana', 9.5, 'SenhaAdmin123')")
    cursor.execute("INSERT INTO alunos VALUES (2, 'Carlos', 7.0, 'SenhaUser456')")
    conn.commit()
    conn.close()

init_db()


# Rota 1: Vulnerável a Reflected XSS

@app.get("/", response_class=HTMLResponse)
def index(busca: str = Query(default="")):
    # O input do usuário (busca) é refletido diretamente no HTML sem sanitização.
    # O ZAP injetará <script>alert(1)</script> aqui e detectará o XSS.
    html_content = f"""
    <html>
        <body>
            <h1>Portal de Notas</h1>
            <p>Você buscou por: <b>{busca}</b></p>
            <form method="GET" action="/buscar">
                <input type="text" name="aluno" placeholder="Nome do aluno">
                <button type="submit">Buscar Notas</button>
            </form>
        </body>
    </html>
    """
    return HTMLResponse(content=html_content)


# Rota 2: Vulnerável a SQL Injection

@app.get("/buscar")
def buscar_aluno(aluno: str):
    conn = sqlite3.connect("universidade.db")
    cursor = conn.cursor()

    # CORREÇÃO DO SQL INJECTION
    # 1. Removemos a f-string.
    # 2. Substituímos a variável diretamente na string por um placeholder '?'.
    # Em bancos de dados como o PostgreSQL (via psycopg2) usar-se-ia '%s',
    # mas no SQLite a convenção é a interrogação.
    query = "SELECT nome, nota FROM alunos WHERE nome = ?"

    try:
        # Passamos a variável 'aluno' como uma tupla (aluno,) no segundo argumento do método execute.
        # A separação entre instrução e dados é feita internamente pelo driver do SQLite.
        cursor.execute(query, (aluno,))

        resultados = cursor.fetchall()
        return {"resultados": resultados}
    except Exception:
        # Substituído o retorno do erro nativo por uma mensagem genérica para evitar Information Disclosure.
        return {"erro": "Ocorreu um erro interno ao processar a busca."}
    finally:
        conn.close()
