import React from 'react';
import {Tag} from '@blueprintjs/core';
import './PostTags.css'

class PostTags extends React.Component {
    genTagsBlock() {
        if (!this.props.tags) {
            return <div className={'post-tag-description-container bp3-skeleton'}/>
        }
        return this.props.tags && this.props.tags.map(e => (
            <Tag key={e.id} interactive={true} className={'post-tag-item'} minimal={true}>{e.name}</Tag>
        ));
    }

    render() {
        return (
            <div className={this.props.className}>
                {this.genTagsBlock()}
            </div>
        );
    }
}

export default PostTags;