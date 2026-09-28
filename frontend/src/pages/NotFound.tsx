import { Compass } from "lucide-react";
import { Link } from "react-router";
import { Empty } from "../components/ui";

export function NotFound() {
  return (
    <Empty icon={<Compass className="size-8" />} title="Nothing here">
      That page doesn't exist.{" "}
      <Link to="/" className="font-medium text-gold underline">
        Back to the dashboard
      </Link>
    </Empty>
  );
}
