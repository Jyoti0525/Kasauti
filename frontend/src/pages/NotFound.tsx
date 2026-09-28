import { Compass } from "lucide-react";
import { Link } from "react-router";
import { Card, Empty } from "../components/ui";

export function NotFound() {
  return (
    <Card>
      <Empty icon={<Compass />} title="Nothing here">
        That page doesn't exist.{" "}
        <Link to="/" className="font-medium text-brass-ink underline">
          Back to the overview
        </Link>
      </Empty>
    </Card>
  );
}
