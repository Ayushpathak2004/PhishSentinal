from fastapi import APIRouter

from ml.evaluation.predict import get_model_metrics

router = APIRouter(prefix="/ml", tags=["Machine Learning"])


@router.get("/metrics")
def read_model_metrics():
    return get_model_metrics()
