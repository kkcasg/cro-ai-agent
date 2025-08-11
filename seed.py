
"""
CRO AI Agent - Database Seed Script
===================================

Script to populate the database with demo data including:
- Admin user (CG)
- Roles and permissions
- Sandbox integrations
- Demo campaigns (WhatsApp and Email)
- Demo contacts and segments
- Basic playbooks
"""

import asyncio
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Add the parent directory to the path so we can import our modules
sys.path.append(str(Path(__file__).parent.parent))

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy import select

from app.core.config import get_settings
from app.core.database import get_async_session, engine
from app.core.security import hash_password
from app.db.models import (
    User, Role, UserRole, Contact, Segment, ContactSegment,
    Campaign, Message, Playbook, Integration, Event,
    UserStatus, ContactStatus, CampaignStatus, CampaignType,
    MessageStatus, IntegrationStatus, AgentRunStatus
)

# Get settings
settings = get_settings()

# Demo data constants
ADMIN_USER = {
    "username": "cg",
    "email": "cg@maispetoficial.com.br",
    "full_name": "CG - Diretor de Receita",
    "password": "CroAgent2024!",
    "phone": "+5511999999999",
    "timezone": "America/Sao_Paulo",
    "language": "pt-BR"
}

ROLES_DATA = [
    {
        "name": "admin",
        "description": "Administrador do sistema com acesso total",
        "permissions": [
            "users.read", "users.write", "users.delete",
            "campaigns.read", "campaigns.write", "campaigns.delete",
            "contacts.read", "contacts.write", "contacts.delete",
            "segments.read", "segments.write", "segments.delete",
            "integrations.read", "integrations.write", "integrations.delete",
            "playbooks.read", "playbooks.write", "playbooks.delete",
            "agents.read", "agents.write", "agents.execute",
            "reports.read", "reports.write",
            "system.admin"
        ],
        "is_system": True
    },
    {
        "name": "cro",
        "description": "Chief Revenue Officer - Acesso completo a growth e vendas",
        "permissions": [
            "campaigns.read", "campaigns.write", "campaigns.delete",
            "contacts.read", "contacts.write", "contacts.delete",
            "segments.read", "segments.write", "segments.delete",
            "integrations.read", "integrations.write",
            "playbooks.read", "playbooks.write", "playbooks.execute",
            "agents.read", "agents.write", "agents.execute",
            "reports.read", "reports.write",
            "analytics.read"
        ],
        "is_system": True
    },
    {
        "name": "marketing",
        "description": "Equipe de Marketing - Campanhas e contatos",
        "permissions": [
            "campaigns.read", "campaigns.write",
            "contacts.read", "contacts.write",
            "segments.read", "segments.write",
            "playbooks.read", "playbooks.execute",
            "agents.read", "agents.execute",
            "reports.read"
        ],
        "is_system": True
    },
    {
        "name": "sales",
        "description": "Equipe de Vendas - Contatos e leads",
        "permissions": [
            "contacts.read", "contacts.write",
            "segments.read",
            "campaigns.read",
            "playbooks.read", "playbooks.execute",
            "agents.read", "agents.execute",
            "reports.read"
        ],
        "is_system": True
    },
    {
        "name": "viewer",
        "description": "Visualizador - Apenas leitura",
        "permissions": [
            "campaigns.read",
            "contacts.read",
            "segments.read",
            "reports.read"
        ],
        "is_system": True
    }
]

INTEGRATIONS_DATA = [
    {
        "name": "WhatsApp Business - Sandbox",
        "provider": "360dialog",
        "status": IntegrationStatus.ACTIVE,
        "config": {
            "api_url": "https://waba-sandbox.360dialog.io",
            "webhook_url": f"{settings.API_V1_STR}/webhooks/whatsapp",
            "phone_number": "+5511999999999",
            "business_account_id": "sandbox_account",
            "verify_token": "cro_agent_verify_token"
        },
        "credentials": {
            "api_key": "sandbox_api_key_encrypted",
            "access_token": "sandbox_access_token_encrypted"
        }
    },
    {
        "name": "Google Workspace - Demo",
        "provider": "google",
        "status": IntegrationStatus.ACTIVE,
        "config": {
            "scopes": [
                "https://www.googleapis.com/auth/gmail.send",
                "https://www.googleapis.com/auth/calendar",
                "https://www.googleapis.com/auth/drive",
                "https://www.googleapis.com/auth/spreadsheets"
            ],
            "redirect_uri": f"{settings.API_V1_STR}/auth/google/callback"
        },
        "credentials": {
            "client_id": "demo_client_id",
            "client_secret": "demo_client_secret_encrypted",
            "refresh_token": "demo_refresh_token_encrypted"
        }
    },
    {
        "name": "Notion - Workspace",
        "provider": "notion",
        "status": IntegrationStatus.ACTIVE,
        "config": {
            "workspace_id": "demo_workspace",
            "database_ids": {
                "campaigns": "demo_campaigns_db",
                "contacts": "demo_contacts_db",
                "tasks": "demo_tasks_db"
            }
        },
        "credentials": {
            "access_token": "demo_notion_token_encrypted"
        }
    },
    {
        "name": "HubSpot - Demo",
        "provider": "hubspot",
        "status": IntegrationStatus.PENDING,
        "config": {
            "portal_id": "demo_portal",
            "api_version": "v3",
            "sync_contacts": True,
            "sync_deals": True
        },
        "credentials": {
            "access_token": "demo_hubspot_token_encrypted"
        }
    }
]

DEMO_CONTACTS = [
    {
        "email": "joao.silva@email.com",
        "phone": "+5511987654321",
        "whatsapp": "+5511987654321",
        "full_name": "João Silva",
        "first_name": "João",
        "last_name": "Silva",
        "status": ContactStatus.ACTIVE,
        "city": "São Paulo",
        "state": "SP",
        "country": "Brasil",
        "company": "Tech Solutions Ltda",
        "job_title": "Gerente de TI",
        "industry": "Tecnologia",
        "total_orders": 3,
        "total_spent": 2500.00,
        "lead_score": 85,
        "lifecycle_stage": "customer",
        "source": "organic",
        "tags": ["vip", "tech", "sao_paulo"],
        "custom_fields": {
            "pet_type": "cachorro",
            "pet_name": "Rex",
            "subscription_plan": "premium"
        }
    },
    {
        "email": "maria.santos@empresa.com.br",
        "phone": "+5511876543210",
        "whatsapp": "+5511876543210",
        "full_name": "Maria Santos",
        "first_name": "Maria",
        "last_name": "Santos",
        "status": ContactStatus.ACTIVE,
        "city": "Rio de Janeiro",
        "state": "RJ",
        "country": "Brasil",
        "company": "Marketing Digital RJ",
        "job_title": "Diretora de Marketing",
        "industry": "Marketing",
        "total_orders": 1,
        "total_spent": 599.00,
        "lead_score": 72,
        "lifecycle_stage": "customer",
        "source": "paid",
        "utm_source": "google",
        "utm_medium": "cpc",
        "utm_campaign": "pets_rj",
        "tags": ["marketing", "rio_de_janeiro", "new_customer"],
        "custom_fields": {
            "pet_type": "gato",
            "pet_name": "Mimi",
            "subscription_plan": "basic"
        }
    },
    {
        "email": "carlos.oliveira@gmail.com",
        "phone": "+5511765432109",
        "whatsapp": "+5511765432109",
        "full_name": "Carlos Oliveira",
        "first_name": "Carlos",
        "last_name": "Oliveira",
        "status": ContactStatus.ACTIVE,
        "city": "Belo Horizonte",
        "state": "MG",
        "country": "Brasil",
        "total_orders": 0,
        "total_spent": 0.00,
        "lead_score": 45,
        "lifecycle_stage": "lead",
        "source": "referral",
        "tags": ["lead", "belo_horizonte", "interested"],
        "custom_fields": {
            "pet_type": "pássaro",
            "pet_name": "Piu",
            "interest": "ração_premium"
        }
    },
    {
        "email": "ana.costa@hotmail.com",
        "phone": "+5511654321098",
        "whatsapp": "+5511654321098",
        "full_name": "Ana Costa",
        "first_name": "Ana",
        "last_name": "Costa",
        "status": ContactStatus.ACTIVE,
        "city": "Curitiba",
        "state": "PR",
        "country": "Brasil",
        "company": "Veterinária Amigos",
        "job_title": "Veterinária",
        "industry": "Veterinária",
        "total_orders": 5,
        "total_spent": 4200.00,
        "lead_score": 95,
        "lifecycle_stage": "customer",
        "source": "organic",
        "tags": ["veterinaria", "curitiba", "high_value"],
        "custom_fields": {
            "professional": True,
            "clinic_name": "Veterinária Amigos",
            "subscription_plan": "professional"
        }
    },
    {
        "email": "pedro.lima@yahoo.com",
        "phone": "+5511543210987",
        "whatsapp": "+5511543210987",
        "full_name": "Pedro Lima",
        "first_name": "Pedro",
        "last_name": "Lima",
        "status": ContactStatus.ACTIVE,
        "city": "Salvador",
        "state": "BA",
        "country": "Brasil",
        "total_orders": 2,
        "total_spent": 1200.00,
        "lead_score": 68,
        "lifecycle_stage": "customer",
        "source": "social",
        "utm_source": "instagram",
        "utm_medium": "social",
        "utm_campaign": "pets_nordeste",
        "tags": ["social_media", "salvador", "repeat_customer"],
        "custom_fields": {
            "pet_type": "cachorro",
            "pet_name": "Bolt",
            "subscription_plan": "standard"
        }
    }
]

SEGMENTS_DATA = [
    {
        "name": "Clientes VIP",
        "description": "Clientes com alto valor de compra e engajamento",
        "criteria": {
            "and": [
                {"field": "total_spent", "operator": "gte", "value": 2000},
                {"field": "lead_score", "operator": "gte", "value": 80},
                {"field": "status", "operator": "eq", "value": "active"}
            ]
        },
        "is_dynamic": True
    },
    {
        "name": "Leads Qualificados",
        "description": "Leads com potencial de conversão",
        "criteria": {
            "and": [
                {"field": "lifecycle_stage", "operator": "eq", "value": "lead"},
                {"field": "lead_score", "operator": "gte", "value": 40},
                {"field": "status", "operator": "eq", "value": "active"}
            ]
        },
        "is_dynamic": True
    },
    {
        "name": "Clientes São Paulo",
        "description": "Clientes da região de São Paulo",
        "criteria": {
            "and": [
                {"field": "state", "operator": "eq", "value": "SP"},
                {"field": "status", "operator": "eq", "value": "active"}
            ]
        },
        "is_dynamic": True
    },
    {
        "name": "Profissionais Veterinários",
        "description": "Veterinários e clínicas parceiras",
        "criteria": {
            "or": [
                {"field": "industry", "operator": "eq", "value": "Veterinária"},
                {"field": "job_title", "operator": "contains", "value": "veterinár"},
                {"field": "custom_fields.professional", "operator": "eq", "value": True}
            ]
        },
        "is_dynamic": True
    },
    {
        "name": "Novos Clientes",
        "description": "Clientes que fizeram primeira compra nos últimos 30 dias",
        "criteria": {
            "and": [
                {"field": "total_orders", "operator": "eq", "value": 1},
                {"field": "lifecycle_stage", "operator": "eq", "value": "customer"},
                {"field": "created_at", "operator": "gte", "value": "30_days_ago"}
            ]
        },
        "is_dynamic": True
    }
]

CAMPAIGNS_DATA = [
    {
        "name": "Boas-vindas WhatsApp - Novos Clientes",
        "description": "Sequência de boas-vindas via WhatsApp para novos clientes",
        "type": CampaignType.WHATSAPP,
        "status": CampaignStatus.RUNNING,
        "content": {
            "messages": [
                {
                    "delay_hours": 0,
                    "content": "🐾 Olá {{first_name}}! Bem-vindo(a) à família +Pet! \n\nObrigado por escolher nossos produtos para o {{pet_name}}. Estamos aqui para ajudar você a cuidar melhor do seu pet! \n\n💚 Equipe +Pet",
                    "media_url": None
                },
                {
                    "delay_hours": 24,
                    "content": "Oi {{first_name}}! 👋\n\nComo está sendo a experiência com nossos produtos? O {{pet_name}} está gostando? \n\nSe tiver alguma dúvida, é só responder esta mensagem! Estamos aqui para ajudar. 🐕🐱",
                    "media_url": None
                },
                {
                    "delay_hours": 72,
                    "content": "{{first_name}}, que tal conhecer nosso programa de fidelidade? 🎁\n\nA cada compra você acumula pontos e ganha descontos especiais! \n\nClique aqui para saber mais: https://maispetoficial.com.br/fidelidade",
                    "media_url": None
                }
            ],
            "triggers": [
                {
                    "event": "first_purchase",
                    "conditions": {
                        "total_orders": 1,
                        "whatsapp_opt_in": True
                    }
                }
            ]
        },
        "settings": {
            "send_time_start": "09:00",
            "send_time_end": "18:00",
            "timezone": "America/Sao_Paulo",
            "respect_opt_out": True,
            "max_messages_per_day": 1
        },
        "budget": 500.00,
        "max_contacts": 1000
    },
    {
        "name": "Newsletter Mensal - Dicas Pet",
        "description": "Newsletter mensal com dicas de cuidados e novidades",
        "type": CampaignType.EMAIL,
        "status": CampaignStatus.SCHEDULED,
        "scheduled_at": datetime.now(timezone.utc) + timedelta(days=7),
        "content": {
            "subject": "🐾 Dicas especiais para o {{pet_name}} - Newsletter {{month_name}}",
            "html_template": """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>Newsletter +Pet</title>
            </head>
            <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <header style="background: #4CAF50; color: white; padding: 20px; text-align: center;">
                    <h1>🐾 +Pet Newsletter</h1>
                </header>
                
                <main style="padding: 20px;">
                    <h2>Olá {{first_name}}!</h2>
                    
                    <p>Esperamos que você e o {{pet_name}} estejam bem! 💚</p>
                    
                    <h3>📚 Dicas do mês:</h3>
                    <ul>
                        <li>Como manter a hidratação do seu pet no verão</li>
                        <li>Exercícios ideais para cada idade</li>
                        <li>Sinais de que seu pet está feliz e saudável</li>
                    </ul>
                    
                    <h3>🛍️ Ofertas especiais:</h3>
                    <p>Aproveite 15% de desconto em toda linha de rações premium!</p>
                    <p><strong>Código: NEWSLETTER15</strong></p>
                    
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="https://maispetoficial.com.br/ofertas" 
                           style="background: #4CAF50; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px;">
                           Ver Ofertas
                        </a>
                    </div>
                </main>
                
                <footer style="background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px;">
                    <p>+Pet - Cuidando do seu melhor amigo</p>
                    <p>Se não deseja mais receber nossos e-mails, <a href="{{unsubscribe_url}}">clique aqui</a></p>
                </footer>
            </body>
            </html>
            """,
            "text_content": """
            Olá {{first_name}}!
            
            Esperamos que você e o {{pet_name}} estejam bem!
            
            DICAS DO MÊS:
            - Como manter a hidratação do seu pet no verão
            - Exercícios ideais para cada idade  
            - Sinais de que seu pet está feliz e saudável
            
            OFERTAS ESPECIAIS:
            Aproveite 15% de desconto em toda linha de rações premium!
            Código: NEWSLETTER15
            
            Acesse: https://maispetoficial.com.br/ofertas
            
            +Pet - Cuidando do seu melhor amigo
            Para cancelar: {{unsubscribe_url}}
            """
        },
        "settings": {
            "send_time": "10:00",
            "timezone": "America/Sao_Paulo",
            "track_opens": True,
            "track_clicks": True,
            "respect_opt_out": True
        },
        "budget": 200.00,
        "max_contacts": 5000
    }
]

PLAYBOOKS_DATA = [
    {
        "name": "Análise de Churn - Relatório Completo",
        "description": "Gera relatório completo de análise de churn com cohorts, causas e plano de ação",
        "category": "analytics",
        "definition": {
            "steps": [
                {
                    "id": "extract_data",
                    "name": "Extrair dados de churn",
                    "agent": "researcher",
                    "config": {
                        "data_sources": ["database", "crm"],
                        "time_period": "{{time_period|default:90}}",
                        "metrics": ["churn_rate", "retention_rate", "ltv"]
                    }
                },
                {
                    "id": "cohort_analysis",
                    "name": "Análise de cohort",
                    "agent": "finance",
                    "config": {
                        "cohort_type": "monthly",
                        "segments": ["all", "by_plan", "by_source"]
                    },
                    "depends_on": ["extract_data"]
                },
                {
                    "id": "identify_causes",
                    "name": "Identificar causas do churn",
                    "agent": "researcher",
                    "config": {
                        "analysis_methods": ["correlation", "survey_data", "support_tickets"],
                        "hypothesis_testing": True
                    },
                    "depends_on": ["cohort_analysis"]
                },
                {
                    "id": "action_plan",
                    "name": "Criar plano de ação",
                    "agent": "planner",
                    "config": {
                        "prioritization": "impact_vs_effort",
                        "timeline": "90_days",
                        "assign_owners": True
                    },
                    "depends_on": ["identify_causes"]
                },
                {
                    "id": "schedule_meeting",
                    "name": "Agendar reunião com stakeholders",
                    "agent": "automation",
                    "config": {
                        "calendar_integration": "google",
                        "attendees": ["marketing", "cs", "product"],
                        "duration": 60,
                        "agenda_template": "churn_review"
                    },
                    "depends_on": ["action_plan"]
                },
                {
                    "id": "create_report",
                    "name": "Gerar relatório final",
                    "agent": "automation",
                    "config": {
                        "format": "pdf",
                        "template": "churn_analysis",
                        "distribution": ["email", "notion"]
                    },
                    "depends_on": ["action_plan"]
                }
            ],
            "variables": {
                "time_period": {
                    "type": "integer",
                    "default": 90,
                    "description": "Período de análise em dias"
                },
                "include_predictions": {
                    "type": "boolean", 
                    "default": True,
                    "description": "Incluir previsões de churn"
                }
            }
        },
        "version": "1.0.0"
    },
    {
        "name": "Campanha WhatsApp - Reativação",
        "description": "Cria e executa campanha de reativação via WhatsApp para clientes inativos",
        "category": "marketing",
        "definition": {
            "steps": [
                {
                    "id": "identify_inactive",
                    "name": "Identificar clientes inativos",
                    "agent": "researcher",
                    "config": {
                        "criteria": {
                            "last_order_days": "{{inactive_days|default:60}}",
                            "total_orders": {"gte": 1},
                            "whatsapp_opt_in": True,
                            "status": "active"
                        }
                    }
                },
                {
                    "id": "segment_customers",
                    "name": "Segmentar clientes por valor",
                    "agent": "researcher",
                    "config": {
                        "segments": [
                            {"name": "high_value", "criteria": {"total_spent": {"gte": 1000}}},
                            {"name": "medium_value", "criteria": {"total_spent": {"gte": 300, "lt": 1000}}},
                            {"name": "low_value", "criteria": {"total_spent": {"lt": 300}}}
                        ]
                    },
                    "depends_on": ["identify_inactive"]
                },
                {
                    "id": "create_messages",
                    "name": "Criar mensagens personalizadas",
                    "agent": "campaign_builder",
                    "config": {
                        "message_variants": {
                            "high_value": "Olá {{first_name}}! Sentimos sua falta... Que tal uma oferta especial de 20% para o {{pet_name}}? 🐾",
                            "medium_value": "Oi {{first_name}}! O {{pet_name}} está precisando de algo especial? Temos 15% de desconto esperando por vocês! 💚",
                            "low_value": "{{first_name}}, que saudade! Volta pra família +Pet com 10% de desconto em qualquer produto! 🎁"
                        },
                        "include_cta": True,
                        "personalization": ["first_name", "pet_name", "last_product"]
                    },
                    "depends_on": ["segment_customers"]
                },
                {
                    "id": "create_campaign",
                    "name": "Criar campanha no sistema",
                    "agent": "automation",
                    "config": {
                        "campaign_type": "whatsapp",
                        "name": "Reativação - {{current_date}}",
                        "schedule": "immediate",
                        "budget": "{{budget|default:1000}}"
                    },
                    "depends_on": ["create_messages"]
                },
                {
                    "id": "execute_campaign",
                    "name": "Executar envios",
                    "agent": "automation",
                    "config": {
                        "batch_size": 100,
                        "delay_between_batches": 300,
                        "respect_business_hours": True,
                        "timezone": "America/Sao_Paulo"
                    },
                    "depends_on": ["create_campaign"]
                },
                {
                    "id": "monitor_results",
                    "name": "Monitorar resultados",
                    "agent": "automation",
                    "config": {
                        "metrics": ["delivery_rate", "response_rate", "conversion_rate"],
                        "alert_thresholds": {
                            "delivery_rate": 0.95,
                            "response_rate": 0.05
                        },
                        "monitoring_period": 72
                    },
                    "depends_on": ["execute_campaign"]
                }
            ],
            "variables": {
                "inactive_days": {
                    "type": "integer",
                    "default": 60,
                    "description": "Dias sem compra para considerar inativo"
                },
                "budget": {
                    "type": "float",
                    "default": 1000.0,
                    "description": "Orçamento da campanha"
                }
            }
        },
        "version": "1.0.0"
    },
    {
        "name": "DRE Simplificado - Análise Mensal",
        "description": "Gera DRE simplificado com análise de margem e insights financeiros",
        "category": "finance",
        "definition": {
            "steps": [
                {
                    "id": "extract_financial_data",
                    "name": "Extrair dados financeiros",
                    "agent": "researcher",
                    "config": {
                        "data_sources": ["csv_upload", "erp_integration"],
                        "period": "{{period|default:current_month}}",
                        "categories": ["revenue", "costs", "expenses"]
                    }
                },
                {
                    "id": "calculate_metrics",
                    "name": "Calcular métricas financeiras",
                    "agent": "finance",
                    "config": {
                        "metrics": [
                            "gross_revenue",
                            "net_revenue", 
                            "gross_margin",
                            "operating_margin",
                            "ebitda",
                            "unit_economics"
                        ],
                        "comparisons": ["previous_month", "same_month_last_year"]
                    },
                    "depends_on": ["extract_financial_data"]
                },
                {
                    "id": "scenario_analysis",
                    "name": "Análise de cenários",
                    "agent": "finance",
                    "config": {
                        "scenarios": ["conservative", "base", "optimistic"],
                        "variables": ["revenue_growth", "cost_reduction", "market_expansion"],
                        "time_horizon": 3
                    },
                    "depends_on": ["calculate_metrics"]
                },
                {
                    "id": "generate_insights",
                    "name": "Gerar insights e recomendações",
                    "agent": "researcher",
                    "config": {
                        "analysis_types": ["trend_analysis", "variance_analysis", "benchmark"],
                        "recommendations": True,
                        "priority_actions": 3
                    },
                    "depends_on": ["scenario_analysis"]
                },
                {
                    "id": "create_dashboard",
                    "name": "Criar dashboard visual",
                    "agent": "automation",
                    "config": {
                        "charts": ["revenue_trend", "margin_analysis", "cost_breakdown"],
                        "format": "html",
                        "interactive": True
                    },
                    "depends_on": ["generate_insights"]
                },
                {
                    "id": "distribute_report",
                    "name": "Distribuir relatório",
                    "agent": "automation",
                    "config": {
                        "recipients": ["cg", "finance_team", "board"],
                        "formats": ["pdf", "excel"],
                        "channels": ["email", "notion"]
                    },
                    "depends_on": ["create_dashboard"]
                }
            ],
            "variables": {
                "period": {
                    "type": "string",
                    "default": "current_month",
                    "description": "Período de análise (current_month, last_month, custom)"
                },
                "include_forecasting": {
                    "type": "boolean",
                    "default": True,
                    "description": "Incluir projeções futuras"
                }
            }
        },
        "version": "1.0.0"
    }
]


async def create_roles(session: AsyncSession) -> dict:
    """Create system roles."""
    print("Creating roles...")
    
    roles = {}
    for role_data in ROLES_DATA:
        # Check if role already exists
        result = await session.execute(
            select(Role).where(Role.name == role_data["name"])
        )
        existing_role = result.scalar_one_or_none()
        
        if not existing_role:
            role = Role(**role_data)
            session.add(role)
            await session.flush()
            roles[role.name] = role
            print(f"  ✓ Created role: {role.name}")
        else:
            roles[existing_role.name] = existing_role
            print(f"  → Role already exists: {existing_role.name}")
    
    return roles


async def create_admin_user(session: AsyncSession, roles: dict) -> User:
    """Create admin user (CG)."""
    print("Creating admin user...")
    
    # Check if user already exists
    result = await session.execute(
        select(User).where(User.username == ADMIN_USER["username"])
    )
    existing_user = result.scalar_one_or_none()
    
    if existing_user:
        print(f"  → User already exists: {existing_user.username}")
        return existing_user
    
    # Create user
    user_data = ADMIN_USER.copy()
    user_data["password_hash"] = hash_password(user_data.pop("password"))
    user_data["status"] = UserStatus.ACTIVE
    user_data["email_verified"] = True
    user_data["email_verified_at"] = datetime.now(timezone.utc)
    
    user = User(**user_data)
    session.add(user)
    await session.flush()
    
    # Assign admin and cro roles
    for role_name in ["admin", "cro"]:
        if role_name in roles:
            user_role = UserRole(
                user_id=user.id,
                role_id=roles[role_name].id,
                assigned_by=user.id
            )
            session.add(user_role)
    
    print(f"  ✓ Created admin user: {user.username}")
    return user


async def create_integrations(session: AsyncSession, admin_user: User):
    """Create sandbox integrations."""
    print("Creating integrations...")
    
    for integration_data in INTEGRATIONS_DATA:
        # Check if integration already exists
        result = await session.execute(
            select(Integration).where(
                Integration.name == integration_data["name"]
            )
        )
        existing_integration = result.scalar_one_or_none()
        
        if not existing_integration:
            integration_data["created_by"] = admin_user.id
            integration = Integration(**integration_data)
            session.add(integration)
            print(f"  ✓ Created integration: {integration.name}")
        else:
            print(f"  → Integration already exists: {existing_integration.name}")


async def create_contacts(session: AsyncSession, admin_user: User) -> list:
    """Create demo contacts."""
    print("Creating demo contacts...")
    
    contacts = []
    for contact_data in DEMO_CONTACTS:
        # Check if contact already exists
        result = await session.execute(
            select(Contact).where(Contact.email == contact_data["email"])
        )
        existing_contact = result.scalar_one_or_none()
        
        if not existing_contact:
            contact_data["created_by"] = admin_user.id
            contact_data["last_interaction_at"] = datetime.now(timezone.utc) - timedelta(days=7)
            
            # Set last_order_at for customers
            if contact_data.get("total_orders", 0) > 0:
                contact_data["last_order_at"] = datetime.now(timezone.utc) - timedelta(days=15)
            
            contact = Contact(**contact_data)
            session.add(contact)
            await session.flush()
            contacts.append(contact)
            print(f"  ✓ Created contact: {contact.full_name}")
        else:
            contacts.append(existing_contact)
            print(f"  → Contact already exists: {existing_contact.full_name}")
    
    return contacts


async def create_segments(session: AsyncSession, admin_user: User, contacts: list):
    """Create demo segments."""
    print("Creating segments...")
    
    segments = []
    for segment_data in SEGMENTS_DATA:
        # Check if segment already exists
        result = await session.execute(
            select(Segment).where(Segment.name == segment_data["name"])
        )
        existing_segment = result.scalar_one_or_none()
        
        if not existing_segment:
            segment_data["created_by"] = admin_user.id
            segment_data["last_calculated_at"] = datetime.now(timezone.utc)
            
            segment = Segment(**segment_data)
            session.add(segment)
            await session.flush()
            
            # Add contacts to segments based on criteria (simplified logic)
            segment_contacts = []
            
            if segment.name == "Clientes VIP":
                segment_contacts = [c for c in contacts if c.total_spent >= 2000 and c.lead_score >= 80]
            elif segment.name == "Leads Qualificados":
                segment_contacts = [c for c in contacts if c.lifecycle_stage == "lead" and c.lead_score >= 40]
            elif segment.name == "Clientes São Paulo":
                segment_contacts = [c for c in contacts if c.state == "SP"]
            elif segment.name == "Profissionais Veterinários":
                segment_contacts = [c for c in contacts if c.industry == "Veterinária"]
            elif segment.name == "Novos Clientes":
                segment_contacts = [c for c in contacts if c.total_orders == 1]
            
            # Add contacts to segment
            for contact in segment_contacts:
                contact_segment = ContactSegment(
                    contact_id=contact.id,
                    segment_id=segment.id,
                    added_by=admin_user.id
                )
                session.add(contact_segment)
            
            segment.contact_count = len(segment_contacts)
            segments.append(segment)
            print(f"  ✓ Created segment: {segment.name} ({segment.contact_count} contacts)")
        else:
            segments.append(existing_segment)
            print(f"  → Segment already exists: {existing_segment.name}")
    
    return segments


async def create_campaigns(session: AsyncSession, admin_user: User, segments: list):
    """Create demo campaigns."""
    print("Creating campaigns...")
    
    campaigns = []
    for campaign_data in CAMPAIGNS_DATA:
        # Check if campaign already exists
        result = await session.execute(
            select(Campaign).where(Campaign.name == campaign_data["name"])
        )
        existing_campaign = result.scalar_one_or_none()
        
        if not existing_campaign:
            campaign_data["created_by"] = admin_user.id
            
            # Assign segment
            if campaign_data["name"].startswith("Boas-vindas"):
                # Assign to "Novos Clientes" segment
                novos_clientes = next((s for s in segments if s.name == "Novos Clientes"), None)
                if novos_clientes:
                    campaign_data["segment_id"] = novos_clientes.id
            elif campaign_data["name"].startswith("Newsletter"):
                # Assign to "Clientes VIP" segment
                vip_segment = next((s for s in segments if s.name == "Clientes VIP"), None)
                if vip_segment:
                    campaign_data["segment_id"] = vip_segment.id
            
            # Set started_at for running campaigns
            if campaign_data["status"] == CampaignStatus.RUNNING:
                campaign_data["started_at"] = datetime.now(timezone.utc) - timedelta(days=1)
            
            campaign = Campaign(**campaign_data)
            session.add(campaign)
            await session.flush()
            campaigns.append(campaign)
            print(f"  ✓ Created campaign: {campaign.name}")
        else:
            campaigns.append(existing_campaign)
            print(f"  → Campaign already exists: {existing_campaign.name}")
    
    return campaigns


async def create_playbooks(session: AsyncSession, admin_user: User):
    """Create demo playbooks."""
    print("Creating playbooks...")
    
    for playbook_data in PLAYBOOKS_DATA:
        # Check if playbook already exists
        result = await session.execute(
            select(Playbook).where(Playbook.name == playbook_data["name"])
        )
        existing_playbook = result.scalar_one_or_none()
        
        if not existing_playbook:
            playbook_data["created_by"] = admin_user.id
            playbook = Playbook(**playbook_data)
            session.add(playbook)
            print(f"  ✓ Created playbook: {playbook.name}")
        else:
            print(f"  → Playbook already exists: {existing_playbook.name}")


async def create_sample_events(session: AsyncSession, contacts: list):
    """Create sample events for analytics."""
    print("Creating sample events...")
    
    events_data = [
        {"name": "page_view", "category": "website", "properties": {"page": "/produtos", "source": "organic"}},
        {"name": "product_view", "category": "ecommerce", "properties": {"product_id": "ração-premium-15kg", "price": 89.90}},
        {"name": "add_to_cart", "category": "ecommerce", "properties": {"product_id": "ração-premium-15kg", "quantity": 1}},
        {"name": "purchase", "category": "ecommerce", "properties": {"order_id": "ORD-001", "value": 89.90}},
        {"name": "whatsapp_message_sent", "category": "messaging", "properties": {"campaign_id": "welcome-series"}},
        {"name": "email_opened", "category": "email", "properties": {"campaign_id": "newsletter-monthly"}},
    ]
    
    for contact in contacts[:3]:  # Only for first 3 contacts
        for event_data in events_data:
            event = Event(
                name=event_data["name"],
                category=event_data["category"],
                properties=event_data["properties"],
                contact_id=contact.id,
                timestamp=datetime.now(timezone.utc) - timedelta(
                    days=random.randint(1, 30),
                    hours=random.randint(0, 23)
                )
            )
            session.add(event)
    
    print(f"  ✓ Created sample events for {len(contacts[:3])} contacts")


async def main():
    """Main seed function."""
    print("🌱 Starting database seed...")
    print(f"Environment: {settings.ENVIRONMENT}")
    print(f"Database URL: {settings.DATABASE_URL}")
    print("-" * 50)
    
    try:
        # Get database session
        async for session in get_async_session():
            # Create roles first
            roles = await create_roles(session)
            
            # Create admin user
            admin_user = await create_admin_user(session, roles)
            
            # Create integrations
            await create_integrations(session, admin_user)
            
            # Create contacts
            contacts = await create_contacts(session, admin_user)
            
            # Create segments
            segments = await create_segments(session, admin_user, contacts)
            
            # Create campaigns
            campaigns = await create_campaigns(session, admin_user, segments)
            
            # Create playbooks
            await create_playbooks(session, admin_user)
            
            # Create sample events
            import random
            await create_sample_events(session, contacts)
            
            # Commit all changes
            await session.commit()
            
            print("-" * 50)
            print("✅ Database seed completed successfully!")
            print(f"Created:")
            print(f"  - {len(roles)} roles")
            print(f"  - 1 admin user (CG)")
            print(f"  - {len(INTEGRATIONS_DATA)} integrations")
            print(f"  - {len(contacts)} contacts")
            print(f"  - {len(segments)} segments")
            print(f"  - {len(campaigns)} campaigns")
            print(f"  - {len(PLAYBOOKS_DATA)} playbooks")
            print(f"  - Sample events for analytics")
            print()
            print("🔑 Admin Login:")
            print(f"  Username: {ADMIN_USER['username']}")
            print(f"  Email: {ADMIN_USER['email']}")
            print(f"  Password: {ADMIN_USER['password']}")
            print()
            print("🚀 You can now start the application!")
            
            break  # Exit the async generator
            
    except Exception as e:
        print(f"❌ Error during seed: {str(e)}")
        raise


if __name__ == "__main__":
    asyncio.run(main())
