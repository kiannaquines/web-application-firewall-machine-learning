import logging
import os
import json
from http import HTTPStatus
from typing import Any, Dict, Optional

from flask import Flask, Response, g, jsonify, request

from waf_ml.runtime import (
    build_detector_from_env,
    build_edge_request_from_environ,
    build_request_from_flask,
    canonicalize_request,
    emit_decision_log,
    evaluate_request,
    new_request_id,
    should_skip_path,
)


def create_app() -> Flask:
    app = Flask(__name__)
    configure_logging()
    detector = build_detector_from_env()
    app.config["WAF_DETECTOR"] = detector
    logger = logging.getLogger("waf.access")

    @app.before_request
    def protect_request() -> Optional[Response]:
        if should_skip_path(request.path):
            return None

        request_id = request.headers.get("X-Request-Id", new_request_id())
        g.request_id = request_id
        canonical_request = build_request_from_flask(request)
        result = evaluate_request(detector, canonical_request)
        emit_decision_log(
            request_id=request_id,
            stage="app",
            result=result,
            model_input=canonicalize_request(
                method=canonical_request.method,
                path=canonical_request.path,
                query=canonical_request.query,
                form=canonical_request.form,
                json_body=canonical_request.json_body,
                headers=canonical_request.headers,
                remote_addr=canonical_request.remote_addr,
                redact_sensitive=True,
            ),
        )
        g.waf_result = result
        if result["action"] == "block":
            return block_response(request_id, result, "application")
        return None

    @app.after_request
    def set_request_id_header(response: Response) -> Response:
        request_id = getattr(g, "request_id", None)
        if request_id:
            response.headers["X-Request-Id"] = request_id
        if not should_skip_path(request.path):
            waf_result = getattr(g, "waf_result", None) or {}
            logger.info(
                json.dumps(
                    {
                        "request_id": request_id or "",
                        "method": request.method,
                        "path": request.path,
                        "status_code": response.status_code,
                        "waf_action": waf_result.get("action", "unknown"),
                        "predicted_class": waf_result.get("predicted_class", ""),
                        "confidence": waf_result.get("confidence", 0.0),
                    }
                )
            )
        return response

    @app.get("/healthz")
    def healthz() -> Response:
        metadata = detector.metadata
        return jsonify(
            {
                "status": "ok",
                "model_loaded": True,
                "selected_model": metadata.get("selected_model"),
                "block_threshold": detector.block_threshold,
                "allow_threshold": detector.allow_threshold,
            }
        )

    @app.route("/__waf__/authorize", methods=["GET", "POST"])
    def authorize() -> Response:
        if request.headers.get("X-WAF-Auth-Request") != "1":
            return jsonify({"error": "forbidden"}), HTTPStatus.FORBIDDEN

        request_id = request.headers.get("X-Request-Id", new_request_id())
        canonical_request = build_edge_request_from_environ(request.environ)
        result = evaluate_request(detector, canonical_request)
        emit_decision_log(
            request_id=request_id,
            stage="edge",
            result=result,
            model_input=canonicalize_request(
                method=canonical_request.method,
                path=canonical_request.path,
                query=canonical_request.query,
                form=canonical_request.form,
                json_body=canonical_request.json_body,
                headers=canonical_request.headers,
                remote_addr=canonical_request.remote_addr,
                redact_sensitive=True,
            ),
        )
        status = HTTPStatus.OK if result["action"] != "block" else HTTPStatus.FORBIDDEN
        response = jsonify(
            {
                "request_id": request_id,
                "action": result["action"],
                "predicted_class": result["predicted_class"],
                "confidence": result["confidence"],
            }
        )
        response.status_code = status
        response.headers["X-Request-Id"] = request_id
        response.headers["X-WAF-Action"] = result["action"]
        response.headers["X-WAF-Predicted-Class"] = result["predicted_class"]
        response.headers["X-WAF-Confidence"] = str(result["confidence"])
        return response

    @app.get("/")
    def index() -> Response:
        return jsonify(
            {
                "message": "ML-backed WAF demo service",
                "routes": ["/search?q=term", "/submit"],
            }
        )

    @app.get("/search")
    def search() -> Response:
        return jsonify(
            {
                "status": "accepted",
                "query": request.args.get("q", ""),
                "request_id": getattr(g, "request_id", ""),
                "waf": public_result(getattr(g, "waf_result", None)),
            }
        )

    @app.post("/submit")
    def submit() -> Response:
        payload = request.get_json(silent=True)
        if payload is None:
            payload = request.form.to_dict(flat=True)
        return jsonify(
            {
                "status": "accepted",
                "received": payload,
                "request_id": getattr(g, "request_id", ""),
                "waf": public_result(getattr(g, "waf_result", None)),
            }
        )

    return app


def public_result(result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not result:
        return {}
    return {
        "action": result["action"],
        "predicted_class": result["predicted_class"],
        "confidence": result["confidence"],
    }


def block_response(request_id: str, result: Dict[str, Any], stage: str) -> Response:
    payload = {
        "error": "request_blocked",
        "request_id": request_id,
        "stage": stage,
        "predicted_class": result["predicted_class"],
        "confidence": result["confidence"],
    }
    response = jsonify(payload)
    response.status_code = HTTPStatus.FORBIDDEN
    return response


def configure_logging() -> None:
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(level=getattr(logging, level_name, logging.INFO))


app = create_app()


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
