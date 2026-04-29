"""
Finance Agent — Financial operations and reporting.

Handles transaction recording, budget management, spending analysis,
invoice creation, and financial reporting.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum
import logging

from agentic_ai.agents.base import BaseAgent, Permission

logger = logging.getLogger(__name__)


class TransactionType(Enum):
    INCOME = "income"
    EXPENSE = "expense"
    TRANSFER = "transfer"


class BudgetStatus(Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    CLOSED = "closed"


@dataclass
class Transaction:
    txn_id: str
    type: TransactionType
    amount: float
    category: str = ""
    description: str = ""
    date: datetime = field(default_factory=datetime.now)


@dataclass
class Budget:
    budget_id: str
    name: str
    total: float = 0.0
    spent: float = 0.0
    categories: Dict[str, float] = field(default_factory=dict)
    status: BudgetStatus = BudgetStatus.DRAFT


@dataclass
class Invoice:
    invoice_id: str
    customer: str
    amount: float
    items: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "draft"
    created_at: datetime = field(default_factory=datetime.now)


class FinanceAgent(BaseAgent):
    """Finance agent for transaction, budget, and invoice management."""

    agent_type = "finance"
    permission = Permission.STANDARD

    def __init__(self, agent_id: str = None, name: str = None,
                 inference_engine=None, state_store=None, message_bus=None):
        super().__init__(agent_id=agent_id, name=name,
                         inference_engine=inference_engine,
                         state_store=state_store, message_bus=message_bus)
        self.transactions: List[Transaction] = []
        self.budgets: List[Budget] = []
        self.invoices: List[Invoice] = []
        self._tools = {
            "record_transaction": self.record_transaction,
            "create_budget": self.create_budget,
            "analyze_spending": self.analyze_spending,
            "create_invoice": self.create_invoice,
            "generate_report": self.generate_report,
        }

    def record_transaction(self, type: str = "expense", amount: float = 0.0,
                           category: str = "", description: str = "") -> Dict[str, Any]:
        try:
            txn_type = TransactionType(type.lower())
        except ValueError:
            return {"error": f"Invalid transaction type: {type}"}
        txn_id = f"TXN-{len(self.transactions)+1:04d}"
        txn = Transaction(txn_id=txn_id, type=txn_type, amount=amount,
                          category=category, description=description)
        self.transactions.append(txn)
        return {"status": "recorded", "txn_id": txn_id, "type": type, "amount": amount, "category": category}

    def create_budget(self, name: str = "", total: float = 0.0,
                      categories: Dict[str, float] = None) -> Dict[str, Any]:
        budget_id = f"BUD-{len(self.budgets)+1:04d}"
        budget = Budget(budget_id=budget_id, name=name, total=total,
                        categories=categories or {})
        self.budgets.append(budget)
        return {"status": "created", "budget_id": budget_id, "name": name, "total": total}

    def analyze_spending(self, period: str = "month", category: str = "") -> Dict[str, Any]:
        expenses = [t for t in self.transactions if t.type == TransactionType.EXPENSE]
        total_spent = sum(t.amount for t in expenses)
        by_category = {}
        for t in expenses:
            by_category[t.category] = by_category.get(t.category, 0) + t.amount
        return {"period": period, "total_spent": total_spent, "transaction_count": len(expenses), "by_category": by_category}

    def create_invoice(self, customer: str = "", amount: float = 0.0,
                       items: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        invoice_id = f"INV-{len(self.invoices)+1:04d}"
        invoice = Invoice(invoice_id=invoice_id, customer=customer, amount=amount, items=items or [])
        self.invoices.append(invoice)
        return {"status": "created", "invoice_id": invoice_id, "customer": customer, "amount": amount}

    def generate_report(self, report_type: str = "summary", period: str = "month") -> Dict[str, Any]:
        income = sum(t.amount for t in self.transactions if t.type == TransactionType.INCOME)
        expenses = sum(t.amount for t in self.transactions if t.type == TransactionType.EXPENSE)
        return {"report_type": report_type, "period": period, "income": income, "expenses": expenses, "net": income - expenses, "budget_count": len(self.budgets), "invoice_count": len(self.invoices)}