
#!/bin/bash

# =============================================================================
# CRO AI Agent - Setup Script Automatizado
# =============================================================================
# 
# Este script automatiza a instalação e configuração do CRO AI Agent
# 
# Uso:
#   ./setup.sh                    # Setup completo
#   ./setup.sh --dev             # Setup para desenvolvimento
#   ./setup.sh --prod            # Setup para produção
#   ./setup.sh --quick           # Setup rápido (sem seed)
#   ./setup.sh --help            # Mostra ajuda
#
# =============================================================================

set -e  # Exit on any error

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Configurações padrão
ENVIRONMENT="development"
QUICK_SETUP=false
SKIP_SEED=false
FORCE_REBUILD=false

# Função para logging
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

# Banner
show_banner() {
    echo -e "${PURPLE}"
    cat << "EOF"
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║                    🤖 CRO AI Agent                           ║
    ║                                                               ║
    ║              Chief Revenue Officer Autônomo                   ║
    ║                                                               ║
    ║    Sistema multi-agente para Growth, Marketing e Vendas      ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Função de ajuda
show_help() {
    echo -e "${WHITE}CRO AI Agent - Setup Script${NC}"
    echo ""
    echo "Uso: $0 [OPÇÕES]"
    echo ""
    echo "Opções:"
    echo "  --dev              Setup para desenvolvimento"
    echo "  --prod             Setup para produção"
    echo "  --quick            Setup rápido (sem dados demo)"
    echo "  --force-rebuild    Força rebuild das imagens Docker"
    echo "  --skip-seed        Pula a criação de dados demo"
    echo "  --help             Mostra esta ajuda"
    echo ""
    echo "Exemplos:"
    echo "  $0                 # Setup completo para desenvolvimento"
    echo "  $0 --prod          # Setup para produção"
    echo "  $0 --quick         # Setup rápido sem dados demo"
    echo ""
}

# Parse argumentos
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dev)
                ENVIRONMENT="development"
                shift
                ;;
            --prod)
                ENVIRONMENT="production"
                shift
                ;;
            --quick)
                QUICK_SETUP=true
                SKIP_SEED=true
                shift
                ;;
            --force-rebuild)
                FORCE_REBUILD=true
                shift
                ;;
            --skip-seed)
                SKIP_SEED=true
                shift
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                error "Opção desconhecida: $1. Use --help para ver as opções disponíveis."
                ;;
        esac
    done
}

# Verificar se comando existe
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Verificar pré-requisitos
check_prerequisites() {
    log "Verificando pré-requisitos..."
    
    # Verificar Docker
    if ! command_exists docker; then
        error "Docker não está instalado. Instale Docker Desktop: https://www.docker.com/products/docker-desktop"
    fi
    
    # Verificar Docker Compose
    if ! command_exists docker-compose && ! docker compose version >/dev/null 2>&1; then
        error "Docker Compose não está instalado ou não é compatível."
    fi
    
    # Verificar se Docker está rodando
    if ! docker info >/dev/null 2>&1; then
        error "Docker não está rodando. Inicie o Docker Desktop."
    fi
    
    # Verificar Git
    if ! command_exists git; then
        warn "Git não está instalado. Algumas funcionalidades podem não funcionar."
    fi
    
    # Verificar versões
    DOCKER_VERSION=$(docker --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    info "Docker versão: $DOCKER_VERSION"
    
    if command_exists docker-compose; then
        COMPOSE_VERSION=$(docker-compose --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        info "Docker Compose versão: $COMPOSE_VERSION"
    else
        info "Usando Docker Compose integrado"
    fi
    
    success "Pré-requisitos verificados com sucesso!"
}

# Gerar chaves de segurança
generate_security_keys() {
    log "Gerando chaves de segurança..."
    
    # JWT Secret (64 caracteres)
    JWT_SECRET=$(openssl rand -hex 32 2>/dev/null || python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || echo "your_super_secret_jwt_key_change_this_in_production_$(date +%s)")
    
    # Encryption Key (32 caracteres)
    ENCRYPTION_KEY=$(openssl rand -hex 16 2>/dev/null || python3 -c "import secrets; print(secrets.token_hex(16))" 2>/dev/null || echo "encryption_key_32_chars_change_this")
    
    success "Chaves de segurança geradas!"
}

# Configurar arquivo .env
setup_environment() {
    log "Configurando arquivo de ambiente..."
    
    if [[ -f .env && "$FORCE_REBUILD" != true ]]; then
        warn "Arquivo .env já existe. Deseja sobrescrever? (y/N)"
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            info "Mantendo arquivo .env existente."
            return
        fi
    fi
    
    # Gerar chaves se necessário
    generate_security_keys
    
    # Criar arquivo .env baseado no template
    if [[ ! -f .env.example ]]; then
        error "Arquivo .env.example não encontrado!"
    fi
    
    cp .env.example .env
    
    # Substituir valores padrão
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        sed -i '' "s/ENVIRONMENT=development/ENVIRONMENT=$ENVIRONMENT/g" .env
        sed -i '' "s/JWT_SECRET_KEY=.*/JWT_SECRET_KEY=$JWT_SECRET/g" .env
        sed -i '' "s/ENCRYPTION_KEY=.*/ENCRYPTION_KEY=$ENCRYPTION_KEY/g" .env
    else
        # Linux
        sed -i "s/ENVIRONMENT=development/ENVIRONMENT=$ENVIRONMENT/g" .env
        sed -i "s/JWT_SECRET_KEY=.*/JWT_SECRET_KEY=$JWT_SECRET/g" .env
        sed -i "s/ENCRYPTION_KEY=.*/ENCRYPTION_KEY=$ENCRYPTION_KEY/g" .env
    fi
    
    # Configurações específicas para produção
    if [[ "$ENVIRONMENT" == "production" ]]; then
        warn "Configuração de produção detectada!"
        warn "Certifique-se de configurar as seguintes variáveis no arquivo .env:"
        warn "- OPENAI_API_KEY"
        warn "- WHATSAPP_API_KEY"
        warn "- GOOGLE_CLIENT_ID e GOOGLE_CLIENT_SECRET"
        warn "- NOTION_API_KEY"
        warn "- DATABASE_URL (para banco de produção)"
        warn "- REDIS_URL (para Redis de produção)"
    fi
    
    success "Arquivo .env configurado para ambiente: $ENVIRONMENT"
}

# Verificar e parar serviços existentes
stop_existing_services() {
    log "Verificando serviços existentes..."
    
    if docker compose ps | grep -q "Up"; then
        warn "Serviços já estão rodando. Parando..."
        docker compose down
        success "Serviços parados."
    fi
}

# Build das imagens Docker
build_images() {
    log "Fazendo build das imagens Docker..."
    
    if [[ "$FORCE_REBUILD" == true ]]; then
        info "Forçando rebuild completo..."
        docker compose build --no-cache
    else
        docker compose build
    fi
    
    success "Build das imagens concluído!"
}

# Iniciar serviços
start_services() {
    log "Iniciando serviços..."
    
    # Iniciar banco e Redis primeiro
    info "Iniciando PostgreSQL e Redis..."
    docker compose up -d postgres redis
    
    # Aguardar banco estar pronto
    info "Aguardando PostgreSQL estar pronto..."
    timeout=60
    while ! docker compose exec postgres pg_isready -U cro_user >/dev/null 2>&1; do
        sleep 2
        timeout=$((timeout - 2))
        if [[ $timeout -le 0 ]]; then
            error "Timeout aguardando PostgreSQL"
        fi
        echo -n "."
    done
    echo ""
    
    # Iniciar backend
    info "Iniciando backend..."
    docker compose up -d backend
    
    # Aguardar backend estar pronto
    info "Aguardando backend estar pronto..."
    timeout=60
    while ! curl -s http://localhost:8000/health >/dev/null 2>&1; do
        sleep 2
        timeout=$((timeout - 2))
        if [[ $timeout -le 0 ]]; then
            error "Timeout aguardando backend"
        fi
        echo -n "."
    done
    echo ""
    
    # Iniciar frontend
    if [[ "$QUICK_SETUP" != true ]]; then
        info "Iniciando frontend..."
        docker compose up -d frontend
    fi
    
    success "Serviços iniciados!"
}

# Executar migrações
run_migrations() {
    log "Executando migrações do banco de dados..."
    
    # Aguardar um pouco mais para garantir que o banco está pronto
    sleep 5
    
    # Executar migrações
    if docker compose exec backend alembic upgrade head; then
        success "Migrações executadas com sucesso!"
    else
        error "Falha ao executar migrações"
    fi
}

# Executar seed de dados
run_seed() {
    if [[ "$SKIP_SEED" == true ]]; then
        info "Pulando criação de dados demo (--skip-seed ou --quick especificado)"
        return
    fi
    
    log "Criando dados demo..."
    
    if docker compose exec backend python scripts/seed.py; then
        success "Dados demo criados com sucesso!"
    else
        warn "Falha ao criar dados demo. Continuando..."
    fi
}

# Verificar saúde dos serviços
check_health() {
    log "Verificando saúde dos serviços..."
    
    # Verificar backend
    if curl -s http://localhost:8000/health | grep -q "ok"; then
        success "✅ Backend: OK (http://localhost:8000)"
    else
        warn "❌ Backend: Falha"
    fi
    
    # Verificar frontend (se não for quick setup)
    if [[ "$QUICK_SETUP" != true ]]; then
        if curl -s http://localhost:3000 >/dev/null 2>&1; then
            success "✅ Frontend: OK (http://localhost:3000)"
        else
            warn "❌ Frontend: Falha"
        fi
    fi
    
    # Verificar banco
    if docker compose exec postgres pg_isready -U cro_user >/dev/null 2>&1; then
        success "✅ PostgreSQL: OK"
    else
        warn "❌ PostgreSQL: Falha"
    fi
    
    # Verificar Redis
    if docker compose exec redis redis-cli ping | grep -q "PONG"; then
        success "✅ Redis: OK"
    else
        warn "❌ Redis: Falha"
    fi
}

# Mostrar informações finais
show_final_info() {
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                               ║${NC}"
    echo -e "${GREEN}║                    🎉 Setup Concluído!                       ║${NC}"
    echo -e "${GREEN}║                                                               ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${WHITE}🌐 URLs de Acesso:${NC}"
    echo -e "   • Backend API:    ${CYAN}http://localhost:8000${NC}"
    echo -e "   • API Docs:       ${CYAN}http://localhost:8000/docs${NC}"
    echo -e "   • Health Check:   ${CYAN}http://localhost:8000/health${NC}"
    
    if [[ "$QUICK_SETUP" != true ]]; then
        echo -e "   • Frontend:       ${CYAN}http://localhost:3000${NC}"
    fi
    
    echo ""
    echo -e "${WHITE}🔑 Credenciais de Acesso (Demo):${NC}"
    echo -e "   • Username:       ${YELLOW}cg${NC}"
    echo -e "   • Email:          ${YELLOW}cg@maispetoficial.com.br${NC}"
    echo -e "   • Password:       ${YELLOW}CroAgent2024!${NC}"
    
    echo ""
    echo -e "${WHITE}📊 Dados Demo Inclusos:${NC}"
    echo -e "   • 5 contatos com diferentes perfis"
    echo -e "   • 5 segmentos dinâmicos"
    echo -e "   • 2 campanhas (WhatsApp e Email)"
    echo -e "   • 3 playbooks prontos"
    echo -e "   • 4 integrações sandbox"
    
    echo ""
    echo -e "${WHITE}🛠️  Comandos Úteis:${NC}"
    echo -e "   • Ver logs:       ${CYAN}docker compose logs -f${NC}"
    echo -e "   • Parar serviços: ${CYAN}docker compose down${NC}"
    echo -e "   • Reiniciar:      ${CYAN}docker compose restart${NC}"
    echo -e "   • Rebuild:        ${CYAN}./setup.sh --force-rebuild${NC}"
    
    echo ""
    echo -e "${WHITE}📚 Próximos Passos:${NC}"
    echo -e "   1. Acesse o frontend em ${CYAN}http://localhost:3000${NC}"
    echo -e "   2. Faça login com as credenciais demo"
    echo -e "   3. Configure suas integrações (APIs)"
    echo -e "   4. Explore os playbooks disponíveis"
    echo -e "   5. Teste os agentes de IA via chat"
    
    if [[ "$ENVIRONMENT" == "production" ]]; then
        echo ""
        echo -e "${RED}⚠️  IMPORTANTE - Produção:${NC}"
        echo -e "   • Configure todas as API keys no arquivo .env"
        echo -e "   • Use banco de dados externo"
        echo -e "   • Configure SSL/HTTPS"
        echo -e "   • Revise configurações de segurança"
    fi
    
    echo ""
    echo -e "${GREEN}Happy Growth Hacking! 🚀${NC}"
    echo ""
}

# Função principal
main() {
    show_banner
    
    # Parse argumentos
    parse_args "$@"
    
    info "Iniciando setup do CRO AI Agent..."
    info "Ambiente: $ENVIRONMENT"
    
    if [[ "$QUICK_SETUP" == true ]]; then
        info "Modo rápido ativado"
    fi
    
    # Executar steps
    check_prerequisites
    setup_environment
    stop_existing_services
    build_images
    start_services
    run_migrations
    run_seed
    
    # Aguardar um pouco para estabilizar
    sleep 5
    
    check_health
    show_final_info
}

# Trap para cleanup em caso de erro
cleanup() {
    if [[ $? -ne 0 ]]; then
        error "Setup falhou! Executando cleanup..."
        docker compose down 2>/dev/null || true
    fi
}

trap cleanup EXIT

# Verificar se está sendo executado como script
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
