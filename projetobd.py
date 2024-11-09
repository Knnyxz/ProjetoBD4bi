import tkinter as tk
from tkinter import messagebox, simpledialog
from pymongo.mongo_client import MongoClient
from cryptography.fernet import Fernet, InvalidToken
import hashlib
from twilio.rest import Client
import base64

# Configuração Twilio
account_sid = 'ACd513154e8cec1f09c79b9ca06d60a239'
auth_token = '46cbd927099c8501559cec1a1ab376b0'
twilio_client = Client(account_sid, auth_token)
twilio_service_sid = 'VAbef645f21b699f05e5b090716de1349e'

# Configuração de segurança e conexão com o MongoDB
uri = "mongodb+srv://Matheus:123456a@cluster0.upeq3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(uri)
db = client['Projeto4bim']
colecao = db['DocAdvogados']
advogados_col = db['Advogados']

# Define chave Fernet fixa para criptografar os dados de maneira consistente
fernet = Fernet('lQF0lpsRfHrWp7KN-WI4_EqlKlj0k_xSTzzh5T_mP2U=')

clientes = dict()
conteudo = dict()
# Funções de criptografia e hashing
def criarhash_conteudo(conteudo):
    hashobj = hashlib.sha256(conteudo.encode())
    return hashobj.hexdigest()

def criptografar_dado(dado):
    criptografado = fernet.encrypt(dado.encode())
    print(f"Dado criptografado: {criptografado}")  # Log do dado criptografado
    return criptografado.decode('utf-8')  # Retorna uma string base64 para armazenar como texto

def descriptografar_dado(dado_criptografado):
    try:
        # Se o dado for em bytes, converte para string
        if isinstance(dado_criptografado, bytes):
            dado_criptografado = dado_criptografado.decode('utf-8')

        # Verifica se o dado está em formato base64
        try:
            base64.b64decode(dado_criptografado, validate=True)
        except base64.binascii.Error:
            print("Dado não está em formato base64 válido, retornando como texto simples.")
            return dado_criptografado  # Retorna o dado original se não for base64

        print(f"Tentando descriptografar: {dado_criptografado}")
        
        # Tentativa de descriptografar o dado
        dado_descriptografado = fernet.decrypt(dado_criptografado.encode('utf-8')).decode()
        print(f"Dado descriptografado com sucesso: {dado_descriptografado}")
        return dado_descriptografado
        
    except InvalidToken:
        print("Erro de descriptografia: Dado inválido ou chave incorreta.")
        return "Erro de descriptografia"  # Retorna uma mensagem clara de erro de descriptografia
    except UnicodeDecodeError as e:
        print(f"Erro de decodificação: {e}")
        return "Erro de decodificação"
    except Exception as e:
        print(f"Erro inesperado ao processar documento: {e}")
        return f"Erro ao processar documento: {e}"  # Retorna mensagem de erro para outros erros
    
# Funções Twilio para envio e verificação de código
def enviar_codigo_verificacao(numero_telefone):
    verification = twilio_client.verify \
        .v2 \
        .services(twilio_service_sid) \
        .verifications \
        .create(to=numero_telefone, channel='sms')
    return verification.status == 'pending'

def verificar_codigo_popup(telefone):
    """Solicita e verifica o código de verificação inserido pelo usuário"""
    while True:
        codigo = simpledialog.askstring("Código de Verificação", "Insira o código recebido por SMS:")
        if codigo is None:
            return False  # Usuário cancelou
        try:
            verification_check = twilio_client.verify \
                .v2.services(twilio_service_sid) \
                .verification_checks \
                .create(to=telefone, code=codigo)
            if verification_check.status == 'approved':
                return True
            else:
                messagebox.showerror("Erro", "Código incorreto. Tente novamente.")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao verificar código: {e}")
            return False

# Funções principais para armazenamento, verificação e compartilhamento
def cadastrar_advogado(nome, telefone, senha):
    telefone_formatado = f"+55{telefone}"
    senha_hash = criarhash_conteudo(senha)
    
    if advogados_col.find_one({"telefone": telefone_formatado}):
        messagebox.showerror("Erro", "Número de telefone já registrado.")
        return False
    
    if enviar_codigo_verificacao(telefone_formatado):
        messagebox.showinfo("Verificação", "Código de verificação enviado para o telefone.")
        if verificar_codigo_popup(telefone_formatado):
            advogados_col.insert_one({
                "nome": nome,
                "telefone": telefone_formatado,
                "senha": senha_hash
            })
            messagebox.showinfo("Sucesso", "Cadastro realizado com sucesso.")
            return True
    else:
        messagebox.showerror("Erro no envio", "Falha ao enviar o código de verificação.")
    return False

def login_advogado(telefone, senha):
    telefone_formatado = f"+55{telefone}"
    senha_hash = criarhash_conteudo(senha)
    advogado = advogados_col.find_one({"telefone": telefone_formatado, "senha": senha_hash})
    if advogado:
        return advogado
    else:
        messagebox.showerror("Erro", "Telefone ou senha incorretos.")
        return None
    

def armazenar_documento(advogado_id, cliente, conteudo):
    hash_conteudo = criarhash_conteudo(conteudo)
    cliente_criptografado = criptografar_dado(cliente)
    conteudo_criptografado = criptografar_dado(conteudo)
    
    colecao.insert_one({
        "advogado_id": advogado_id,
        "cliente": cliente_criptografado,
        "caso": conteudo_criptografado,
        "integridade": hash_conteudo,
        "permissoes": [advogado_id]
    })
    messagebox.showinfo("Sucesso", "Documento armazenado com segurança!")

def verificar_integridade(advogado_id, cliente, caso):
    documento = colecao.find_one({"advogado_id": advogado_id, "permissoes": advogado_id})
    if documento:
        cliente_descriptografado = descriptografar_dado(documento["cliente"])
        conteudo_descriptografado = descriptografar_dado(documento["caso"])
        
        if cliente_descriptografado == cliente and conteudo_descriptografado == caso:
            hash_atual = criarhash_conteudo(caso)
            if hash_atual == documento["integridade"]:
                return True
            else:
                messagebox.showwarning("Integridade", "O documento foi alterado.")
        else:
            messagebox.showwarning("Dados Incorretos", "Os dados fornecidos não coincidem.")
    else:
        messagebox.showerror("Erro", "Documento não encontrado ou você não tem permissão para acessar.")
    return False

def compartilhar_documento(advogado_id, advogado_destino_id, cliente, caso):
    documento = colecao.find_one({"advogado_id": advogado_id})
    if documento:
        colecao.update_one(
            {"_id": documento["_id"]},
            {"$addToSet": {"permissoes": advogado_destino_id}}
        )
        messagebox.showinfo("Compartilhamento", "Documento compartilhado com sucesso!")
    else:
        messagebox.showerror("Erro", "Documento não encontrado para compartilhamento.")

def buscar_documentos(criterio, advogado_id):
    resultados = []
    documentos = colecao.find({"advogado_id": advogado_id})
    
    for doc in documentos:
        try:
            # Tenta descriptografar os dados do cliente e do caso
            cliente_descriptografado = descriptografar_dado(doc["cliente"])  # Corrigido para acessar `doc`
            conteudo_descriptografado = descriptografar_dado(doc["caso"])    # Corrigido para acessar `doc`
            
            # Verifica se o critério está presente no cliente ou no caso
            if criterio.lower() in cliente_descriptografado.lower() or criterio.lower() in conteudo_descriptografado.lower():
                resultados.append({
                    "cliente": cliente_descriptografado,
                    "caso": conteudo_descriptografado,
                    "integridade": doc["integridade"]
                })
        except InvalidToken:
            resultados.append({
                    "cliente": clientes,
                    "caso": conteudo,
                    "integridade": doc["integridade"]
            })
        except Exception as e:
            print(f"Erro ao processar documento: {e}")

    return resultados



# Interface Tkinter com design aprimorado
def iniciar_programa():
    janela = tk.Tk()
    janela.title("Gestão de Casos Jurídicos")
    janela.geometry("400x400")
    janela.configure(bg="#3a3a3a")

    # Estilos
    fonte_padrao = ("Arial", 12)
    cor_fundo = "#3a3a3a"
    cor_fonte = "#909090"
    cor_botao = "#982a2a"
    cor_botao_texto = "#b1b1b1"

    # Frame principal
    frame = tk.Frame(janela, bg=cor_fundo, padx=20, pady=20)
    frame.pack(expand=True, fill="both")

    def limpar_widgets():
        for widget in frame.winfo_children():
            widget.destroy()

    def menu_login():
        limpar_widgets()

        def acao_login():
            telefone = entrada_telefone.get()
            senha = entrada_senha.get()
            advogado = login_advogado(telefone, senha)
            if advogado:
                menu_principal(advogado["_id"])

        tk.Label(frame, text="Login", font=("Arial", 14, "bold"), fg=cor_fonte, bg=cor_fundo).pack(pady=10)

        tk.Label(frame, text="Telefone (somente números):", font=fonte_padrao, bg=cor_fundo, fg=cor_fonte).pack(anchor="w")
        entrada_telefone = tk.Entry(frame, font=fonte_padrao, width=30, relief="solid")
        entrada_telefone.pack(pady=(0, 10), fill="x")

        tk.Label(frame, text="Senha:", font=fonte_padrao, bg=cor_fundo, fg=cor_fonte).pack(anchor="w")
        entrada_senha = tk.Entry(frame, font=fonte_padrao, width=30, relief="solid", show="*")
        entrada_senha.pack(pady=(0, 10), fill="x")

        btn_login = tk.Button(
            frame, text="Login", font=fonte_padrao, bg=cor_botao, fg=cor_botao_texto,
            activebackground="#9d6363", relief="flat", command=acao_login
        )
        btn_login.pack(pady=5, fill="x")

        btn_cadastro = tk.Button(
            frame, text="Cadastrar", font=fonte_padrao, bg=cor_botao, fg=cor_botao_texto,
            activebackground="#9d6363", relief="flat", command=menu_cadastro
        )
        btn_cadastro.pack(pady=5, fill="x")

    def menu_cadastro():
        limpar_widgets()

        def acao_cadastrar():
            nome = entrada_nome.get()
            telefone = entrada_telefone.get()
            senha = entrada_senha.get()
            if nome and telefone and senha:
                cadastrar_advogado(nome, telefone, senha)
                menu_login()
            else:
                messagebox.showwarning("Campos vazios", "Preencha todos os campos.")

        tk.Label(frame, text="Cadastro de Advogado", font=("Arial", 14, "bold"), fg=cor_fonte, bg=cor_fundo).pack(pady=10)

        tk.Label(frame, text="Nome:", font=fonte_padrao, bg=cor_fundo, fg=cor_fonte).pack(anchor="w")
        entrada_nome = tk.Entry(frame, font=fonte_padrao, width=30, relief="solid")
        entrada_nome.pack(pady=(0, 10), fill="x")

        tk.Label(frame, text="Telefone (somente números):", font=fonte_padrao, bg=cor_fundo, fg=cor_fonte).pack(anchor="w")
        entrada_telefone = tk.Entry(frame, font=fonte_padrao, width=30, relief="solid")
        entrada_telefone.pack(pady=(0, 10), fill="x")

        tk.Label(frame, text="Senha:", font=fonte_padrao, bg=cor_fundo, fg=cor_fonte).pack(anchor="w")
        entrada_senha = tk.Entry(frame, font=fonte_padrao, width=30, relief="solid", show="*")
        entrada_senha.pack(pady=(0, 10), fill="x")

        btn_cadastrar = tk.Button(
            frame, text="Cadastrar", font=fonte_padrao, bg=cor_botao, fg=cor_botao_texto,
            activebackground="#9d6363", relief="flat", command=acao_cadastrar
        )
        btn_cadastrar.pack(pady=5, fill="x")

        btn_voltar = tk.Button(
            frame, text="Voltar", font=fonte_padrao, bg=cor_botao, fg=cor_botao_texto,
            activebackground="#9d6363", relief="flat", command=menu_login
        )
        btn_voltar.pack(pady=5, fill="x")

    def menu_principal(advogado_id):
        limpar_widgets()
        
        tk.Label(frame, text="Gestão de Casos Jurídicos", font=("Arial", 16, "bold"), fg=cor_fonte, bg=cor_fundo).pack(pady=(0, 20))

        # Botões do menu principal
        tk.Button(
            frame, text="Armazenar Caso", font=fonte_padrao, bg=cor_botao, fg=cor_botao_texto,
            activebackground="#9d6363", relief="flat", command=lambda: menu_armazenar(advogado_id)
        ).pack(pady=5, fill="x")

        tk.Button(
            frame, text="Pesquisar Documentos", font=fonte_padrao, bg=cor_botao, fg=cor_botao_texto,
            activebackground="#9d6363", relief="flat", command=lambda: menu_pesquisar(advogado_id)
        ).pack(pady=5, fill="x")

        btn_compartilhar = tk.Button(
            frame, text="Compartilhar Documento", font=fonte_padrao, bg=cor_botao, fg=cor_botao_texto,
            activebackground="#9d6363", relief="flat", command=lambda: menu_compartilhar(advogado_id)
        )
        btn_compartilhar.pack(pady=5, fill="x")

    def menu_armazenar(advogado_id):
        limpar_widgets()
        
        def acao_armazenar():
            cliente = entrada_cliente.get()
            caso = entrada_caso.get()
            if cliente and caso:
                armazenar_documento(advogado_id, cliente, caso)
                clientes = cliente
                conteudo = caso
                messagebox.showinfo("Sucesso", "Documento armazenado com segurança!")
                menu_principal(advogado_id)
            else:
                messagebox.showwarning("Campos vazios", "Preencha todos os campos.")

        tk.Label(frame, text="Armazenar um novo caso", font=("Arial", 14, "bold"), fg=cor_fonte, bg=cor_fundo).pack(pady=10)
        
        tk.Label(frame, text="Nome do Cliente:", font=fonte_padrao, bg=cor_fundo, fg=cor_fonte).pack(anchor="w")
        entrada_cliente = tk.Entry(frame, font=fonte_padrao, width=30, relief="solid")
        entrada_cliente.pack(pady=(0, 10), fill="x")

        tk.Label(frame, text="Nome do Caso:", font=fonte_padrao, bg=cor_fundo, fg=cor_fonte).pack(anchor="w")
        entrada_caso = tk.Entry(frame, font=fonte_padrao, width=30, relief="solid")
        entrada_caso.pack(pady=(0, 20), fill="x")

        tk.Button(
            frame, text="Armazenar Caso", font=fonte_padrao, bg=cor_botao, fg=cor_botao_texto,
            activebackground="#9d6363", relief="flat", command=acao_armazenar
        ).pack(pady=5, fill="x")

        tk.Button(
            frame, text="Voltar", font=fonte_padrao, bg=cor_botao, fg=cor_botao_texto,
            activebackground="#9d6363", relief="flat", command=lambda: menu_principal(advogado_id)
        ).pack(pady=5, fill="x")

    def menu_pesquisar(advogado_id):
        limpar_widgets()
        
        def acao_pesquisar():
            criterio = entrada_pesquisa.get()
            resultados = buscar_documentos(criterio, advogado_id)
            if resultados:
                exibir_resultados(resultados, advogado_id)
            else:
                messagebox.showinfo("Resultados da Pesquisa", "Nenhum documento encontrado para o critério fornecido.")

        tk.Label(frame, text="Pesquisar Documentos", font=("Arial", 14, "bold"), fg=cor_fonte, bg=cor_fundo).pack(pady=10)
        
        tk.Label(frame, text="Pesquisar por Cliente ou Caso:", font=fonte_padrao, bg=cor_fundo, fg=cor_fonte).pack(anchor="w")
        entrada_pesquisa = tk.Entry(frame, font=fonte_padrao, width=30, relief="solid")
        entrada_pesquisa.pack(pady=(0, 10), fill="x")

        tk.Button(
            frame, text="Pesquisar", font=fonte_padrao, bg=cor_botao, fg=cor_botao_texto,
            activebackground="#9d6363", relief="flat", command=acao_pesquisar
        ).pack(pady=5, fill="x")

        tk.Button(
            frame, text="Voltar", font=fonte_padrao, bg=cor_botao, fg=cor_botao_texto,
            activebackground="#9d6363", relief="flat", command=lambda: menu_principal(advogado_id)
        ).pack(pady=5, fill="x")

    def exibir_resultados(resultados, advogado_id):
        limpar_widgets()
        
        tk.Label(frame, text="Resultados da Pesquisa", font=("Arial", 14, "bold"), fg=cor_fonte, bg=cor_fundo).pack(pady=10)
        
        for doc in resultados:
            try:
                # Tenta descriptografar os dados do cliente e do caso
                cliente_descriptografado = descriptografar_dado(doc["cliente"])
                caso_descriptografado = descriptografar_dado(doc["caso"])
                
                # Exibe o resultado descriptografado
                tk.Label(frame, text=f"Cliente: {cliente_descriptografado} | Caso: {caso_descriptografado}", font=fonte_padrao, bg=cor_fundo, fg=cor_fonte).pack(anchor="w")
            
            except InvalidToken:
                messagebox.showerror("Erro de Descriptografia", "Dado criptografado inválido ou chave incorreta.")
            except Exception as e:
                messagebox.showerror("Erro", f"Erro ao exibir documento: {e}")
        
        tk.Button(
            frame, text="Voltar", font=fonte_padrao, bg=cor_botao, fg=cor_botao_texto,
            activebackground="#9d6363", relief="flat", command=lambda: menu_pesquisar(advogado_id)
        ).pack(pady=5, fill="x")

    menu_login()
    janela.mainloop()


    def menu_compartilhar(advogado_id):
        limpar_widgets()
        
        def acao_compartilhar():
          advogado_destino_id = entrada_destino_id.get()
          cliente = entrada_cliente.get()
          caso = entrada_caso.get()
          if advogado_destino_id and cliente and caso:
              compartilhar_documento(advogado_id, advogado_destino_id, cliente, caso)
          else:
              messagebox.showwarning("Campos vazios", "Preencha todos os campos.")

        tk.Label(frame, text="Compartilhar Documento", font=("Arial", 14, "bold"), fg=cor_fonte, bg=cor_fundo).pack(pady=10)

        tk.Label(frame, text="ID do Advogado (destino):", font=fonte_padrao, bg=cor_fundo, fg=cor_fonte).pack(anchor="w")
        entrada_destino_id = tk.Entry(frame, font=fonte_padrao, width=30, relief="solid")
        entrada_destino_id.pack(pady=(0, 10), fill="x")

        tk.Label(frame, text="Nome do Cliente:", font=fonte_padrao, bg=cor_fundo, fg=cor_fonte).pack(anchor="w")
        entrada_cliente = tk.Entry(frame, font=fonte_padrao, width=30, relief="solid")
        entrada_cliente.pack(pady=(0, 10), fill="x")

        tk.Label(frame, text="Nome do Caso:", font=fonte_padrao, bg=cor_fundo, fg=cor_fonte).pack(anchor="w")
        entrada_caso = tk.Entry(frame, font=fonte_padrao, width=30, relief="solid")
        entrada_caso.pack(pady=(0, 20), fill="x")

        btn_compartilhar_caso = tk.Button(
            frame, text="Compartilhar", font=fonte_padrao, bg=cor_botao, fg=cor_botao_texto,
            activebackground="#9d6363", relief="flat", command=acao_compartilhar
        )
        btn_compartilhar_caso.pack(pady=5, fill="x")

        btn_voltar = tk.Button(
            frame, text="Voltar", font=fonte_padrao, bg=cor_botao, fg=cor_botao_texto,
            activebackground="#9d6363", relief="flat", command=lambda: menu_principal(advogado_id)
        )
        btn_voltar.pack(pady=5, fill="x")

    menu_login()
    janela.mainloop()

# Conexão ao MongoDB e inicialização do programa
try:
    client.admin.command('ping')
    iniciar_programa()
except Exception as e:
    print("Erro na conexão:", e)
