import React from "react";

import './PostHeader.css'

class PostHeader extends React.Component {
    getTitleBlock() {
        if (!this.props.title) {
            return (
                <div className={"skeleton-container"}>
                    <h1 className={"pt-skeleton title " + this.props.className}>Lorem ipsum dolor sit amet</h1>
                </div>
            );
        }
        return <h1 className={"title " + this.props.className}>{this.props.title}</h1>
    }

    render() {
        return this.getTitleBlock();
    }
}

export default PostHeader;